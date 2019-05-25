#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <syslog.h>
#include <signal.h>
//#include <pwd.h>
//#include <grp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "net.h"
#include "error.h"
#include "netlink_events.h"
#include "inotify_common.h"

// TODO ipv6
// TODO map uids and gids to real names
  // implement getgrgid and getpwuid myself because cant link these static
// TODO permissions, attributes, owner, groupships of files
// TODO keep track of processes as they are executed to give EXIT better context
   // This will need something like 'ps' to get initial list of processes so
   // we have data for processes that have been running longer than this program
// TODO limits? /proc/X/limits
// TODO atexit() handler to log when this dies

// https://www.kernel.org/doc/Documentation/connector/connector.txt

/*
 * Globals
 */
sock_t          sock;
int             inotify;
bool            daemonize       = false;
bool            quiet           = false;
bool            use_syslog      = true;
bool            log_to_file     = false;
char            *outfile        = "/var/log/noawareness.json.log";
FILE            *outfilep;
char            *pidfile        = "/var/run/noawareness.pid";
char            *inotifyconfig  = "inotify.conf";
bool            remote_logging  = true;
char            *log_server     = "127.0.0.1";
port_t          log_server_port = 55555;
unsigned long   maxsize         = 50000000; // 50mb
char            hostname[HOST_NAME_MAX];

/*
 * Prototypes
 */
static void handle_sighup(int, siginfo_t *, void *);


void output(const char *msg) {
  if (!daemonize)
    if (!quiet)
      printf("%s\n", msg);

  if (remote_logging)
    sockprintf(sock, "%s\r\n", msg);

  if (log_to_file)
    fprintf(outfilep, "%s\n", msg);
}

void msg(const char *msg) {
  if (use_syslog)
    syslog(LOG_INFO | LOG_USER, "%s", msg);

  if (!daemonize)
    printf("%s\n", msg);
}

static void handle_netlink_message(struct cn_msg *cn_message) {
  struct proc_event   *event;
  char                *msg;
  char                *environment;

  msg = NULL;
  event = (struct proc_event *)cn_message->data;

  switch (event->what) {
  case PROC_EVENT_NONE:
    break;

  case PROC_EVENT_FORK:
    msg = handle_PROC_EVENT_FORK(event);
    break;

  case PROC_EVENT_EXEC:
    msg = handle_PROC_EVENT_EXEC(event);
    environment = handle_PROC_EVENT_EXEC_environment(event);
    output(environment);
    break;

  case PROC_EVENT_EXIT:
    msg = handle_PROC_EVENT_EXIT(event);
    break;

  case PROC_EVENT_UID:
    msg = handle_PROC_EVENT_UID(event);
    break;

  case PROC_EVENT_PTRACE:
    msg = handle_PROC_EVENT_PTRACE(event);
    break;

   case PROC_EVENT_GID:
    msg = handle_PROC_EVENT_GID(event);
    break;

  case PROC_EVENT_SID:
    handle_PROC_EVENT_SID(event);
    break;

  case PROC_EVENT_COMM:
    handle_PROC_EVENT_COMM(event);
    break;

  case PROC_EVENT_COREDUMP:
    handle_PROC_EVENT_COREDUMP(event);
    break;

  default:
    error("event %d not handled yet", event->what);
    break;
  }

  /* If we have data to output, deal with it. */
  if (msg != NULL)
    output(msg);
}

void write_pid_file(const char *path, pid_t pid) {
  FILE        *pidfile;

  pidfile = fopen(path, "w");
  if (pidfile == NULL)
    error_fatal("Unable to open PID file %s: %s", path, strerror(errno));

  fprintf(pidfile, "%d", pid);
  fclose(pidfile);
}

static void select_netlink(int netlink, struct sockaddr_nl nl_kernel, struct cn_msg *cn_message) {
  int                 recv_length;
  socklen_t           nl_kernel_len;
  struct nlmsghdr     *nlh;
  char                buf[1024] = {0};

  nl_kernel_len = sizeof(nl_kernel);

  recv_length = recvfrom(netlink,
                         buf,
                         sizeof(buf),
                         0,
                         (struct sockaddr *)&nl_kernel,
                         &nl_kernel_len);
  nlh = (struct nlmsghdr *)buf;

  if ((recv_length < 1) || (nl_kernel.nl_pid != 0))
    return;

  while (NLMSG_OK(nlh, recv_length)) {
    cn_message = NLMSG_DATA(nlh);

    if ((nlh->nlmsg_type == NLMSG_NOOP) || (nlh->nlmsg_type == NLMSG_ERROR))
      continue;

    if (nlh->nlmsg_type == NLMSG_OVERRUN)
      break;

    handle_netlink_message(cn_message);

    if (nlh->nlmsg_type == NLMSG_DONE) {
      break;
    } else {
      nlh = NLMSG_NEXT(nlh, recv_length);
    }
  }
}

static void select_inotify(int inotify) {
  char                  *p;
  int                   res;
  char                  buf[INOTIFY_BUF_LEN];
  struct inotify_event  *event;

  res = read(inotify, buf, sizeof(buf));
  if ((res == 0) || (res == -1))
    error_fatal("read() on inotify fd: %s", strerror(errno));

  for (p = buf; p < buf + res; ) {
    event = (struct inotify_event *) p;
    inotify_process_event(inotify, event);
    p += sizeof(struct inotify_event) + event->len;
  }
}

FILE *open_log_file(const char *outfile) {
  FILE *fp;

  fp = fopen(outfile, "a+");
  if (fp == NULL)
    error_fatal("Unable to open log file: %s", strerror(errno));

  return fp;
}

static void install_sighup_handler() {
  struct sigaction act = {0};

  act.sa_sigaction = &handle_sighup;
  act.sa_flags = SA_SIGINFO;

  if (sigaction(SIGHUP, &act, NULL) < 0)
    error_fatal("sigaction(): %s", strerror(errno));
}

static void handle_sighup(int sig, siginfo_t *siginfo, void *context) {
  // TODO inotify config reload
  msg("Caught SIGHUP.");

  if (log_to_file) {
    msg("Reloading JSON log file");
    fclose(outfilep);
    outfilep = open_log_file(outfile);
  }

  msg("Reloading inotify config");
  inotify_add_files(inotify, inotifyconfig);
}

static void usage(const char *progname) {
  fprintf(stderr, "usage: %s [-h?]\n\n", progname);
  fprintf(stderr, "    -h/-?      - Print this menu and exit.\n");
  fprintf(stderr, "    -d         - Daemonize. Default: %s\n",
	  daemonize ? "yes" : "no");
  fprintf(stderr, "    -i <path>  - Path to inotify config file. Default: %s\n",
	  inotifyconfig);
  fprintf(stderr, "    -m <bytes> - Max size of file to hash. Default: %ld\n",
	  maxsize);
  fprintf(stderr, "    -o <file>  - Outfile for JSON output, Default: %s\n",
	  outfile);
  fprintf(stderr, "    -O         - Toggle local JSON logging. Default: %s\n",
	  log_to_file ? "true" : "false");
  fprintf(stderr, "    -P <path>  - Path to PID file. Default: %s\n", pidfile);
  fprintf(stderr, "    -r         - Toggle remote logging. Default: %s\n",
	  remote_logging ? "true" : "false");
  fprintf(stderr, "    -s <IP>    - Remote log server. Default: %s\n",
	  log_server);
  fprintf(stderr, "    -S         - Toggle syslog. Default: %s\n",
	  use_syslog ? "true" : "false");
  fprintf(stderr, "    -p <port>  - Port of remote server. Default: %d\n",
	  log_server_port);
  fprintf(stderr, "    -q         - Toggle quiet mode. Default: %s\n",
	  quiet ? "true" : "false");

  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  int                     opt;
  int                     err;
  pid_t                   pid;
  sock_t                  netlink;
  struct sockaddr_nl      nl_userland, nl_kernel;
  struct nlmsghdr         *nl_header;
  struct cn_msg           *cn_message;
  char                    buf[1024];
  enum proc_cn_mcast_op   *mcop_msg;
  fd_set                  fdset;


  /* Parse CLI options */
  while((opt = getopt(argc, argv, "qrdm:s:So:Op:rP:i:h?")) != -1) {
    switch (opt) {
    case 'd': /* Daemonize */
      daemonize = daemonize ? false : true;
      break;

    case 'i': /* inotify config file location */
      inotifyconfig = optarg;
      break;

    case 'm': /* Maximum filesize to hash */
      maxsize = atol(optarg);
      break;

    case 'o': /* Path to outfile */
      // TODO check if writeable
      outfile = optarg;
      log_to_file = true;
      break;

    case 'O': /* Toggle logging to a file */
      log_to_file = log_to_file ? false : true;
      break;

    case 'p': /* Remote server port */
      log_server_port = atoi(optarg);
      break;

    case 'P': /* PID file location */
      pidfile = optarg;
      break;

    case 'q': /* Toggle quiet mode */
      quiet = quiet ? false : true;
      break;

    case 'r': /* Toggle remote logging */
      remote_logging = remote_logging ? false : true;
      break;

    case 's': /* Remote server */
      log_server = optarg;
      if (!validate_ipv4(log_server))
	  error_fatal("Invalid IP address: %s", log_server);
      break;

    case 'S': /* Toggle syslog */
      use_syslog = use_syslog ? false : true;
      break;

    /* All of these effectively call usage(), so roll them over */
    case 'h':
    case '?':
    default:
      usage(argv[0]);
    }
  }

  /* Set up syslog() */
  if (use_syslog)
    openlog("noawareness", LOG_PID, LOG_USER);

  /* SIGHUP handler. */
  install_sighup_handler();

  /* Open log file. */
  if (log_to_file)
    outfilep = open_log_file(outfile);

  /* Get our hostname for reporting purposes. */
  if (gethostname(hostname, sizeof(hostname)) == -1)
    error_fatal("gethostname(): %s", strerror(errno));

  /* Create inotify descriptor. */
  inotify = inotify_init();
  if (inotify == -1)
    error_fatal("inotify_init(): %s", strerror(errno));

  inotify_add_files(inotify, inotifyconfig);

  /* Create netlink socket. */
  netlink = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (netlink == -1)
    error_fatal("error creating netlink socket: %s", strerror(errno));

  nl_kernel.nl_family = AF_NETLINK;
  nl_kernel.nl_groups = CN_IDX_PROC;
  nl_kernel.nl_pid    = 1;

  nl_userland.nl_family = AF_NETLINK;
  nl_userland.nl_groups = CN_IDX_PROC;
  nl_userland.nl_pid    = getpid();

  err = bind(netlink, (struct sockaddr *)&nl_userland, sizeof(nl_userland));
  if (err == -1)
    error_fatal("error binding netlink socket: %s", strerror(errno));

  memset(buf, 0x00, sizeof(buf));
  nl_header = (struct nlmsghdr *)buf;
  cn_message = (struct cn_msg *)NLMSG_DATA(nl_header);
  mcop_msg = (enum proc_cn_mcast_op *)&cn_message->data[0];
  *mcop_msg = PROC_CN_MCAST_LISTEN;

  cn_message->id.idx = CN_IDX_PROC;
  cn_message->id.val = CN_VAL_PROC;
  cn_message->seq    = 0;
  cn_message->ack    = 0;
  cn_message->len    = sizeof(enum proc_cn_mcast_op);

  nl_header->nlmsg_len   = \
    NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
  nl_header->nlmsg_type  = NLMSG_DONE;
  nl_header->nlmsg_flags = 0;
  nl_header->nlmsg_seq   = 0;
  nl_header->nlmsg_pid   = getpid();

  err = send(netlink, nl_header, nl_header->nlmsg_len, 0);
  if (err != nl_header->nlmsg_len) {
    error("send: %s", strerror(errno));
    close(netlink);
    return EXIT_FAILURE;
  }

  /* Create UDP socket for sending the logs. */
  if (remote_logging) {
    struct sockaddr_in  s_addr;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
      error_fatal("socket(): %s", strerror(errno));

    bzero(&s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr(log_server);
    s_addr.sin_port = htons(log_server_port);

    /* connect() UDP socket so you dont have to use sendto() */
    err = connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr));
    if (err == -1)
      error_fatal("connect(): %s", strerror(errno));
  }

  /* Daemonize the process if desired. */
  if (daemonize) {
    pid = fork();
    if (pid < 0)
      error_fatal("fork(): %s", strerror(errno));

    else if (pid > 0) {
      write_pid_file(pidfile, pid);
      exit(EXIT_SUCCESS);
    }
  }

  /* Set up select loop and get some. */
  int setsize = netlink > inotify ? netlink + 1 : inotify + 1;
  for(;;) {
    FD_ZERO(&fdset);
    FD_SET(netlink, &fdset);
    FD_SET(inotify, &fdset);

    if (select(setsize, &fdset, NULL, NULL, NULL) < 0)
      if (errno != EINTR)
	error_fatal("select(): %s", strerror(errno));

    for(int i = 0; i < FD_SETSIZE; i++) {
      if (FD_ISSET(i, &fdset)) {
        if (i == inotify)
          select_inotify(inotify);

        else if (i == netlink)
          select_netlink(netlink, nl_kernel, cn_message);

        else
          error("select(): unhandled fd: %d", i);
      }
    }
  } /* for(;;) */

  /* Shouldn't ever get here */
  close(netlink);
  close(sock);
	    closelog();

  return EXIT_SUCCESS;
}
