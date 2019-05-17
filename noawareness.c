#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
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

// TODO syslog
// TODO inotify event log to remote server
// TODO JSON inotify event output
// TODO SIGHUP reload inotify.conf
// TODO map uids and gids to real names
  // implement getgrgid and getpwuid myself because cant link these static
// TODO permissions, attributes, owner, groupships of files
// TODO keep track of processes as they are executed to give EXIT better context
   // This will need something like 'ps' to get initial list of processes so
   // we have data for processes that have been running longer than this program
// TODO environment?? /proc/X/environ
   // This is a good idea, because there are a lot of neat things to glean from
   // a processes environment. The downside is that environments can get quite
   // large, so logging this every time is kind of insane.
     // daniel@stingray ~ % env |wc -c
     // 3203
     // daniel@stingray ~ % env |gzip -f - |wc -c
     // 1294
     // daniel@stingray ~ % env |gzip -f - |base64 |wc -c
     // 1751  <- need it encoded so it doesnt jack up formatting.
// TODO limits? /proc/X/limits
// TODO cwd /proc/X/cwd
// TODO print startup message, add atexit() handler to log when this dies

// https://www.kernel.org/doc/Documentation/connector/connector.txt

/*
 * Globals
 */
sock_t  sock;
bool    daemonize = false;
char   *pidfile = "/var/run/noawareness.pid";
char    hostname[HOST_NAME_MAX];
char    *inotifyconfig = NULL;
char    *log_server = NULL;
port_t  log_server_port = 55555;


void handle_netlink_message(struct cn_msg *cn_message) {
  struct proc_event   *event;
  char                *msg;

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
    printf("\nevent %d not handled yet\n", event->what);
    break;
  }

  /* If we have data to output, deal with it. */
  if (msg != NULL) {
    if (!daemonize)
      printf("%s\n", msg);
    sockprintf(sock, "%s\r\n", msg);
  }
}

void write_pid_file(const char *path, pid_t pid) {
  FILE        *pidfile;

  pidfile = fopen(path, "w");
  if (pidfile == NULL)
    error_fatal("Unable to open PID file %s: %s\n", path, strerror(errno));

  fprintf(pidfile, "%d", pid);
  fclose(pidfile);
}

void usage(const char *progname) {
  error("usage: %s [-h?]\n\n", progname);
  error("    -h/-?     - print this menu and exit.\n");
  error("    -d        - Daemonize. Default: %s\n",
	(daemonize == true) ? "yes" : "no");
  error("    -p <path> - Path to PID file. Default: %s\n", pidfile);

  exit(EXIT_FAILURE);
}

void select_netlink(int netlink, struct sockaddr_nl nl_kernel, struct cn_msg *cn_message) {
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

void select_inotify(int inotify) {
  char                  *p;
  int                   res;
  char                  buf[INOTIFY_BUF_LEN];
  struct inotify_event  *event;

  res = read(inotify, buf, sizeof(buf));
  if ((res == 0) || (res == -1))
    error_fatal("read() on inotify fd: %s\n", strerror(errno));

  for (p = buf; p < buf + res; ) {
    event = (struct inotify_event *) p;
    inotify_process_event(inotify, event);
    p += sizeof(struct inotify_event) + event->len;
  }
}

int main(int argc, char *argv[]) {
  int                     opt;
  int                     err;
  pid_t                   pid;
  sock_t                  netlink;
  int                     inotify;
  struct sockaddr_nl      nl_userland, nl_kernel;
  struct nlmsghdr         *nl_header;
  struct cn_msg           *cn_message;
  char                    buf[1024];
  enum proc_cn_mcast_op   *mcop_msg;
  fd_set                  fdset;


  /* Parse CLI options */
  while((opt = getopt(argc, argv, "dp:i:h?")) != -1) {
    switch (opt) {
    case 'd': /* Daemonize */
      daemonize = (daemonize == true) ? false : true;
      break;

    case 'p': /* Remote server port */
      log_server_port = atoi(optarg);
      break;

    case 's': /* Remote server */
      log_server = optarg;
      break;

    case 'P': /* PID file location */
      pidfile = optarg;
      break;

    case 'i': /* inotify config file location */
      inotifyconfig = optarg;
      break;

      /* All of these effectively call usage(), so roll them over */
    case 'h':
    case '?':
    default:
      usage(argv[0]);
    }
  }

  /* Get our hostname for reporting purposes */
  if (gethostname(hostname, sizeof(hostname)) == -1)
    error_fatal("gethostname(): %s\n", strerror(errno));

  /* Create inotify descriptor */
  inotify = inotify_init();
  if (inotify == -1)
    error_fatal("inotify_init(): %s\n", strerror(errno));

  inotify_add_files(inotify, inotifyconfig);

  /* Create netlink socket */
  netlink = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (netlink == -1)
    error_fatal("error creating netlink socket: %s\n", strerror(errno));

  nl_kernel.nl_family = AF_NETLINK;
  nl_kernel.nl_groups = CN_IDX_PROC;
  nl_kernel.nl_pid    = 1;

  nl_userland.nl_family = AF_NETLINK;
  nl_userland.nl_groups = CN_IDX_PROC;
  nl_userland.nl_pid    = getpid();

  err = bind(netlink, (struct sockaddr *)&nl_userland, sizeof(nl_userland));
  if (err == -1)
    error_fatal("error binding netlink socket: %s\n", strerror(errno));

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
    error("send: %s\n", strerror(errno));
    close(netlink);
    return EXIT_FAILURE;
  }

  /* Create udp socket for sending the logs */
  // TODO resolve hostnames
  struct sockaddr_in  s_addr;
  //struct hostent      *server;
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    error_fatal("socket(): %s\n", strerror(errno));

  //server = gethostbyname("localhost");
  //if (server == NULL)
  //    error_fatal("gethostbyname(): %s\n", strerror(errno));

  bzero(&s_addr, sizeof(s_addr));
  s_addr.sin_family = AF_INET;
  s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  s_addr.sin_port = htons(55555);

  /* connect() so you dont have to use sendto() */
  err = connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr));
  if (err == -1)
    error_fatal("connect(): %s\n", strerror(errno));

  /* Daemonize the process if desired. */
  if (daemonize) {
    pid = fork();
    if (pid < 0)
      error_fatal("fork(): %s\n", strerror(errno));

    else if (pid > 0) {
      write_pid_file(pidfile, pid);
      exit(EXIT_SUCCESS);
    }
  }

  /* Set up select loop and get some */
  int setsize = netlink > inotify ? netlink + 1 : inotify + 1;
  for(;;) {
    FD_ZERO(&fdset);
    FD_SET(netlink, &fdset);
    FD_SET(inotify, &fdset);

    if (select(setsize, &fdset, NULL, NULL, NULL) < 0)
      error_fatal("select(): %s\n", strerror(errno));

    for(int i = 0; i < FD_SETSIZE; i++) {
      if (FD_ISSET(i, &fdset)) {
        if (i == inotify)
          select_inotify(inotify);

        else if (i == netlink)
          select_netlink(netlink, nl_kernel, cn_message);

        else
          error("idk wtf this fd is: %d\n", i);
      }
    }
  } /* for(;;) */

  /* Shouldn't ever get here */
  close(netlink);
  close(sock);

  return EXIT_SUCCESS;
}
