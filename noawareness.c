#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include <json-c/json.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "net.h"
#include "md5.h"
#include "proc.h"
#include "time_common.h"
#include "string_common.h"

// TODO syslog
// TODO map uids and gids to real names
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
// TODO add inotify-watch stuff
    // idk if its better to put it into one process, or two?
    // writes to passwd, shadow, sudoers, sudoers.d, ...
// TODO watch pcap too
// https://www.kernel.org/doc/Documentation/connector/connector.txt

/*
 * Globals
 */
sock_t  sock;
bool    daemonize = false;
char    *pidfile = "/var/run/noawareness.pid";
char    hostname[HOST_NAME_MAX];


/* handle_PROC_EVENT_FORK() - Handle PROC_EVENT_FORK events.
 *
 * The following are available for this event:
 *  - pid_t parent_pid
 *  - pid_t parent_tgid
 *  - pid_t child_pid
 *  - pid_t child_tgid
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event.
 *
 * TODO
 * - Deal with parent_pid and child_pid being the same somehow (see below)
 */
char *handle_PROC_EVENT_FORK(struct proc_event *event) {
    char                *exepath;
    bool                deleted;
    char                *md5;
    struct proc_status  status;
    json_object         *jobj = json_object_new_object();
    json_object         *j_timestamp = json_object_new_double(timestamp());
    json_object         *j_hostname = json_object_new_string(hostname);
    json_object         *j_exepath;
    json_object         *j_deleted;
    json_object         *j_name;
    json_object         *j_uid;
    json_object         *j_euid;
    json_object         *j_gid;
    json_object         *j_egid;
    json_object         *j_md5;
    json_object         *j_parent_pid;
    json_object         *j_parent_tgid;
    json_object         *j_child_pid;
    json_object         *j_child_tgid;
    json_object         *j_cmdline;
    json_object         *j_event_type = json_object_new_string("fork");

    status = proc_get_status(event->event_data.fork.parent_pid);
    exepath = proc_get_exe_path(event->event_data.fork.parent_pid);

    /* If files are running, but have been deleted on disk, the
     * symbolic link in /proc/PID/exe has (deleted) appended to
     * it. This can still be opened and hashed with original values:
     *
     * Hashing this link vs the real path on disk seems to be faster.
     *
     * % cp /usr/bin/yes blah
     * % ./blah >/dev/null &
     * [1] 227
     * % ls /proc/227/exe -l
     * lrwxrwxrwx 1 d d 0 May 12 11:53 /proc/227/exe -> /home/d/blah*
     * % rm blah
     * % ls /proc/22711/exe -l
     * lrwxrwxrwx 1 d d 0 May 12 11:53 /proc/227/exe -> '/home/d/blah (deleted)'
     * % md5sum /proc/227/exe
     * 33d8c8e092458e35ed45a709aa64a99b  /proc/227/exe
     * % md5sum /usr/bin/yes
     * 33d8c8e092458e35ed45a709aa64a99b  /usr/bin/yes
     */
    deleted = endswith(exepath, "(deleted)");
    md5 = md5_digest_file(proc_exe_path(event->event_data.fork.parent_pid));

    j_exepath     = json_object_new_string(exepath);
    j_deleted     = json_object_new_boolean(deleted);
    j_name        = json_object_new_string(status.name);
    j_uid         = json_object_new_int(status.uid);
    j_euid        = json_object_new_int(status.euid);
    j_gid         = json_object_new_int(status.gid);
    j_egid        = json_object_new_int(status.egid);
    j_md5         = json_object_new_string(md5);
    j_parent_pid  = json_object_new_int(event->event_data.fork.parent_pid);
    j_parent_tgid = json_object_new_int(event->event_data.fork.parent_tgid);
    j_child_pid   = json_object_new_int(event->event_data.fork.child_pid);
    j_child_tgid  = json_object_new_int(event->event_data.fork.child_tgid);
    j_cmdline     = json_object_new_string(proc_get_cmdline(event->event_data.fork.parent_pid));

    json_object_object_add(jobj, "timestamp", j_timestamp);
    json_object_object_add(jobj, "hostname", j_hostname);
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "process_name", j_name);
    json_object_object_add(jobj, "exepath", j_exepath);
    json_object_object_add(jobj, "deleted", j_deleted);
    json_object_object_add(jobj, "cmdline", j_cmdline);
    json_object_object_add(jobj, "uid", j_uid);
    json_object_object_add(jobj, "euid", j_euid);
    json_object_object_add(jobj, "gid", j_gid);
    json_object_object_add(jobj, "egid", j_egid);
    json_object_object_add(jobj, "md5", j_md5);
    json_object_object_add(jobj, "parent_pid", j_parent_pid);
    json_object_object_add(jobj, "parent_tgid", j_parent_tgid);
    json_object_object_add(jobj, "child_pid", j_child_pid);
    json_object_object_add(jobj, "child_tgid", j_child_tgid);

    return (char *)json_object_to_json_string(jobj);
     // TODO parent and child are same data when this event is caught.
     //printf("%s %s\n", proc_get_exe_path(event->event_data.fork.parent_pid),
	//	       proc_get_cmdline(event->event_data.fork.child_pid));
}

/* handle_PROC_EVENT_EXEC() - Handle PROC_EVENT_EXEC events.
 *
 * The following are available for this event:
 *  - pid_t process_pid
 *  - pid_t process_tgid
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event.
 */
char *handle_PROC_EVENT_EXEC(struct proc_event *event) {
    char        *exefile;
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
    json_object *j_hostname = json_object_new_string(hostname);
    json_object *j_exepath;
    json_object *j_process_pid;
    json_object *j_process_tgid;
    json_object *j_md5;
    json_object *j_cmdline;
    json_object *j_event_type = json_object_new_string("exec");

    exefile        = proc_get_exe_path(event->event_data.exec.process_pid);
    j_exepath      = json_object_new_string(exefile);
    j_process_pid  = json_object_new_int(event->event_data.exec.process_pid);
    j_process_tgid = json_object_new_int(event->event_data.exec.process_tgid);
    j_cmdline      = json_object_new_string(proc_get_cmdline(event->event_data.exec.process_pid));
    j_md5          = json_object_new_string(md5_digest_file(exefile));

    json_object_object_add(jobj, "timestamp", j_timestamp);
    json_object_object_add(jobj, "hostname", j_hostname);
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_process_pid);
    json_object_object_add(jobj, "tgid", j_process_tgid);
    json_object_object_add(jobj, "md5", j_md5);
    json_object_object_add(jobj, "exename", j_exepath);
    json_object_object_add(jobj, "cmdline", j_cmdline);

    return (char *)json_object_to_json_string(jobj);
}

/* handle_PROC_EVENT_EXIT() - Handle PROC_EVENT_EXIT events.
 *
 * The following are available for this event:
 *  - pid_t process_pid
 *  - pid_t process_tgid
 *  - u32 exit_code
 *  - u32 exit_signal
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event.
 */
char *handle_PROC_EVENT_EXIT(struct proc_event *event) {
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
    json_object *j_hostname = json_object_new_string(hostname);
    json_object *j_pid;
    json_object *j_tgid;
    json_object *j_exitcode;
    json_object *j_signal;
    json_object *j_event_type = json_object_new_string("exit");

    j_pid         = json_object_new_int(event->event_data.exit.process_pid);
    j_tgid        = json_object_new_int(event->event_data.exit.process_tgid);
    j_exitcode    = json_object_new_int(event->event_data.exit.exit_code);
    j_signal      = json_object_new_int(event->event_data.exit.exit_signal);

    json_object_object_add(jobj, "timestamp", j_timestamp);
    json_object_object_add(jobj, "hostname", j_hostname);
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "exit_code", j_exitcode);
    json_object_object_add(jobj, "signal", j_signal);

    return (char *)json_object_to_json_string(jobj);
}

/* handle_PROC_EVENT_UID() - Handle PROC_EVENT_UID events.
 * handle_PROC_EVENT_GID() - Handle PROC_EVENT_GID events.
 *
 * The following are availabie for this event:
 *  - pid_t process_ppid
 *  - pid_t process_tgid
 *  - union { u32 ruid; u32 rgid } r
 *  - union { u32 euid; u32 egid } e
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event
 *
 * Note:
 *     The handle_PROC_EVENT_UID and handle_PROC_EVENT_GID functions
 *     are nearly identical.
 */
char *handle_PROC_EVENT_UID(struct proc_event *event) {
    // TODO lookup pid exefile/name, hash, ...
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
    json_object *j_hostname = json_object_new_string(hostname);
    json_object *j_pid;
    json_object *j_tgid;
    json_object *j_ruid;
    json_object *j_euid;
    json_object *j_event_type = json_object_new_string("uid");

    j_pid  = json_object_new_int(event->event_data.id.process_pid);
    j_tgid = json_object_new_int(event->event_data.id.process_tgid);
    j_ruid = json_object_new_int(event->event_data.id.r.ruid);
    j_euid = json_object_new_int(event->event_data.id.e.euid);

    json_object_object_add(jobj, "timestamp", j_timestamp);
    json_object_object_add(jobj, "hostname", j_hostname);
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "ruid", j_ruid);
    json_object_object_add(jobj, "euid", j_euid);

    return (char *)json_object_to_json_string(jobj);
}

char *handle_PROC_EVENT_GID(struct proc_event *event) {
    // TODO lookup pid exefile/name, hash, ...
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
    json_object *j_hostname = json_object_new_string(hostname);
    json_object *j_pid;
    json_object *j_tgid;
    json_object *j_rgid;
    json_object *j_egid;
    json_object *j_event_type = json_object_new_string("gid");

    j_pid  = json_object_new_int(event->event_data.id.process_pid);
    j_tgid = json_object_new_int(event->event_data.id.process_tgid);
    j_rgid = json_object_new_int(event->event_data.id.r.rgid);
    j_egid = json_object_new_int(event->event_data.id.e.egid);

    json_object_object_add(jobj, "timestamp", j_timestamp);
    json_object_object_add(jobj, "hostname", j_hostname);
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "rgid", j_rgid);
    json_object_object_add(jobj, "egid", j_egid);

    return (char *)json_object_to_json_string(jobj);
}

/* handle_PROC_EVENT_PTRACE() - Handle PROC_EVENT_PTRACE events.
 *
 * The following are availabie for this event:
 *  - pid_t process_ppid
 *  - pid_t process_tgid
 *  - pid_t tracer_pid
 *  - pid_t tracer_tgid
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event
 *
 * Note:
 *     This is triggered when setsid() happens. I am not sure of the
 *     forensic implications of this event, so it currently does nothing.
 */
char *handle_PROC_EVENT_PTRACE(struct proc_event *event) {
    // TODO hash of tracer, exefile/name, etc...
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
    json_object *j_hostname = json_object_new_string(hostname);
    json_object *j_pid;
    json_object *j_tgid;
    json_object *j_tracer_pid;
    json_object *j_tracer_tgid;
    json_object *j_event_type = json_object_new_string("ptrace");

    j_pid         = json_object_new_int(event->event_data.ptrace.process_pid);
    j_tgid        = json_object_new_int(event->event_data.ptrace.process_tgid);
    j_tracer_pid  = json_object_new_int(event->event_data.ptrace.tracer_pid);
    j_tracer_tgid = json_object_new_int(event->event_data.ptrace.tracer_tgid);

    json_object_object_add(jobj, "timestamp", j_timestamp);
    json_object_object_add(jobj, "hostname", j_hostname);
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "tracer_pid", j_tracer_pid);
    json_object_object_add(jobj, "tracer_tgid", j_tracer_tgid);

    return (char *)json_object_to_json_string(jobj);
}

/* handle_PROC_EVENT_SID() - Handle PROC_EVENT_SID events.
 *
 * The following are availabie for this event:
 *  - pid_t process_ppid
 *  - pid_t process_tgid
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event
 *
 * Note:
 *     This is triggered when setsid() happens. I am not sure of the
 *     forensic implications of this event, so it currently does nothing.
 */
void handle_PROC_EVENT_SID(struct proc_event *event) {
    return;
}

/* handle_PROC_EVENT_COMM() - Handle PROC_EVENT_COMM events.
 *
 * The following are availabie for this event:
 *  - pid_t process_ppid
 *  - pid_t process_tgid
 *  - char comm[16]
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event
 *
 * Note:
 *     I am not sure what exactly triggers this right now, or the forensic
 *     implications of these events. Despite this, there seem to be quite
 *     a few of these events.
 */
void handle_PROC_EVENT_COMM(struct proc_event *event) {
    return;
}

/* handle_PROC_EVENT_COREDUMP() - Handle PROC_EVENT_COREDUMP events.
 *
 * The following are availabie for this event:
 *  - pid_t process_ppid
 *  - pid_t process_tgid
 *  - pid_t parent_pid
 *  - pid_t parent_tgid
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event
 *
 * TODO this.
 */
void handle_PROC_EVENT_COREDUMP(struct proc_event *event) {
    return;
}


void handle_message(struct cn_msg *cn_message) {
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
	if (!daemonize) printf("%s\n", msg);
	sockprintf(sock, "%s\r\n", msg);
    }
}

void write_pid_file(const char *path, pid_t pid) {
    FILE        *pidfile;

    pidfile = fopen(path, "w");
    if (pidfile == NULL) {
	fprintf(stderr, "Unable to open PID file %s: %s\n",
		path, strerror(errno));
	exit(EXIT_FAILURE);
    }

    fprintf(pidfile, "%d", pid);
    fclose(pidfile);
}

void usage(const char *progname) {
    fprintf(stderr, "usage: %s [-h?]\n\n", progname);
    fprintf(stderr, "    -h/-?     - print this menu and exit.\n");
    fprintf(stderr, "    -d        - Daemonize. Default: %s\n",
	    (daemonize == true) ? "yes" : "no");
    fprintf(stderr, "    -p <path> - Path to PID file. Default: %s\n", pidfile);

    exit(EXIT_FAILURE);
}

void select_netlink(int netlink, struct sockaddr_nl nl_kernel, struct cn_msg *cn_message) {
    int                 recv_length;
    socklen_t           nl_kernel_len;
    struct nlmsghdr     *nlh;
    char                buf[1024];

    memset(buf, 0x00, sizeof(buf));
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

	handle_message(cn_message);

	if (nlh->nlmsg_type == NLMSG_DONE) {
	    break;
	} else {
	    nlh = NLMSG_NEXT(nlh, recv_length);
	}
    }
}

int main(int argc, char *argv[]) {
    int                     opt;
    int                     error;
    pid_t                   pid;
    sock_t                  netlink;
    int                     inotify;
    struct sockaddr_nl      nl_userland, nl_kernel;
    struct nlmsghdr         *nl_header;
    struct cn_msg           *cn_message;
    char                    buf[1024];
    enum proc_cn_mcast_op   *mcop_msg;
    fd_set                  fdset;
    int                     i;

    /* Parse CLI options */
    while((opt = getopt(argc, argv, "dp:h?")) != -1) {
	switch (opt) {
	case 'd': /* Daemonize */
	    daemonize = (daemonize == true) ? false : true;
	    break;
	case 'p': /* PID file location */
	    pidfile = optarg;
	    break;

	/* All of these effectively call usage(), so roll them over */
	case 'h':
	case '?':
	default:
	    usage(argv[0]);
	}
    }

    /* Get our hostname once for reporting purposes */
    if (gethostname(hostname, sizeof(hostname)) == -1) {
	fprintf(stderr, "gethostname(): %s\n", strerror(errno));
	return EXIT_FAILURE;
    }

    /* Daemonize the process if desired
     * TODO move this after everything gets set up */
    if (daemonize) {
	pid = fork();
	if (pid < 0) {
	    fprintf(stderr, "fork(): %s\n", strerror(errno));
	    exit(EXIT_FAILURE);
	} else if (pid > 0) {
	    write_pid_file(pidfile, pid);
	    exit(EXIT_SUCCESS);
	}
    }

    /* Create inotify descriptor */
    inotify = inotify_init();
    if (inotify == -1) {
	fprintf(stderr, "inotify_init(): %s\n", strerror(errno));
	return EXIT_FAILURE;
    }

    /* Create netlink socket */
    netlink = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (netlink == -1) {
        fprintf(stderr,
            "error creating netlink socket: %s\n",
            strerror(errno));
        return EXIT_FAILURE;
    }

    nl_kernel.nl_family = AF_NETLINK;
    nl_kernel.nl_groups = CN_IDX_PROC;
    nl_kernel.nl_pid    = 1;

    nl_userland.nl_family = AF_NETLINK;
    nl_userland.nl_groups = CN_IDX_PROC;
    nl_userland.nl_pid    = getpid();

    error = bind(netlink, (struct sockaddr *)&nl_userland, sizeof(nl_userland));
    if (error == -1) {
        fprintf(stderr, "error binding netlink socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

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

    error = send(netlink, nl_header, nl_header->nlmsg_len, 0);
    if (error != nl_header->nlmsg_len) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        close(netlink);
        return EXIT_FAILURE;
    }

    /* Create udp socket for sending the logs */
    struct sockaddr_in  s_addr;
    //struct hostent      *server;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket(): %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    //server = gethostbyname("localhost");
    //if (server == NULL) {
    //    fprintf(stderr, "gethostbyname(): %s\n", strerror(errno));
    //    return EXIT_FAILURE;
    //}

    bzero(&s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    s_addr.sin_port = htons(55555);

    /* connect() so you dont have to use sendto() */
    error = connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr));
    if (error == -1) {
	fprintf(stderr, "connect(): %s\n", strerror(errno));
	return EXIT_FAILURE;
    }

    /* Set up select fd set */
    FD_ZERO(&fdset);
    FD_SET(netlink, &fdset);
    FD_SET(inotify, &fdset);

    if (select(FD_SETSIZE, &fdset, NULL, NULL, NULL) < 0) {
	fprintf(stderr, "select(): %s\n", strerror(errno));
	return EXIT_FAILURE;
    }

    // TODO print startup message, add atexit() handler to log when this dies
    for(;;) {
	for(i = 0; i < FD_SETSIZE; i++) {
	    if (FD_ISSET(i, &fdset)) {
		if (i == inotify) {
		    fprintf(stderr, "inotify!!!\n");
		}

		if (i == netlink) {
		    select_netlink(netlink, nl_kernel, cn_message);
		}
	    }
	}
    } /* for(;;) */

    /* Shouldn't ever get here */
    close(netlink);
    close(sock);

    return EXIT_SUCCESS;
}
