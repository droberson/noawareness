#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <json-c/json.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "md5_common.h"
#include "proc_common.h"
#include "string_common.h"

// TODO flood protection; if someone runs a repetitive shell script or similar,
    // don't send the logs over and over.
// TODO keep track of processes as they are executed to give EXIT better context
// TODO deal with (deleted) files as exefile
    // TODO read /proc/X/maps, get actual map's md5sum. this should work if
    // the (deleted) suffix in exepath is there
// TODO remote logging
// TODO daemonize
    // TODO pid file + watchdog script
// TODO entropy of file.
// TODO environment?? /proc/X/environ
// TODO limits? /proc/X/limits
// TODO cwd /proc/X/cwd
// TODO add inotify-watch stuff
    // writes to passwd, shadow, sudoers, sudoers.d, ...

// https://www.kernel.org/doc/Documentation/connector/connector.txt

int sock;

int sockprintf(int s, const char *fmt, ...) {
    int     n;
    char    buf[8192];
    va_list vl;

    memset(buf, 0x00, sizeof(buf));

    va_start(vl, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, vl);
    va_end(vl);

    return send(s, buf, n, 0);
}

double timestamp() {
    double          result;
    struct timeval  tv;

    // TODO error check
    gettimeofday(&tv, NULL);

    result = tv.tv_sec + tv.tv_usec * 0.0000001;
    return result;
}

/*
 * for the handle_PROC_EVENT_* functions, see linux/cn_proc.h for structure
 * of events
 */

/*
 * pid_t parent_pid
 * pid_t parent_tgid
 * pid_t child_pid
 * pid_t child_tgid
 */
char *handle_PROC_EVENT_FORK(struct proc_event *event) {
    char                *exepath;
    char                *md5;
    char                *msg;
    struct proc_status  status;

    json_object         *jobj = json_object_new_object();
    json_object         *j_timestamp = json_object_new_double(timestamp());
    json_object         *j_exepath;
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

    // TODO if this is deleted, read the map file
    md5 = (strstr(exepath, "(deleted)") == NULL) ? md5_digest_file(exepath) : "deleted";

    j_exepath     = json_object_new_string(exepath);
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
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "process_name", j_name);
    json_object_object_add(jobj, "exepath", j_exepath);
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

    msg = (char *)json_object_to_json_string(jobj);
    printf("%s\n", msg);

    return msg;
     // TODO this only shows the parent, until child exec()s; this ends up
     // showing the same pids for parent and child..
     //printf("%s %s\n", proc_get_exe_path(event->event_data.fork.parent_pid),
	//	       proc_get_cmdline(event->event_data.fork.child_pid));
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 */
char *handle_PROC_EVENT_EXEC(struct proc_event *event) {
    char        *exefile;
    char        *msg;
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
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
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_process_pid);
    json_object_object_add(jobj, "tgid", j_process_tgid);
    json_object_object_add(jobj, "md5", j_md5);
    json_object_object_add(jobj, "exename", j_exepath);
    json_object_object_add(jobj, "cmdline", j_cmdline);

    msg = (char *)json_object_to_json_string(jobj);
    printf("%s\n", msg);

    return msg;
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 * u32 exit_code
 * u32 exit_signal
 */
char *handle_PROC_EVENT_EXIT(struct proc_event *event) {
    char        *msg;
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
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
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "exit_code", j_exitcode);
    json_object_object_add(jobj, "signal", j_signal);

    msg = (char *)json_object_to_json_string(jobj);
    printf("%s\n", msg);

    return msg;
}

/*
 * pid_t process_ppid
 * pid_t process_tgid
 * union { u32 ruid; u32 rgid } r
 * union { u32 euid; u32 egid } e
 */
char *handle_PROC_EVENT_UID(struct proc_event *event) {
    // TODO lookup pid exefile/name, hash, ...
    char        *msg;
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
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
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "ruid", j_ruid);
    json_object_object_add(jobj, "euid", j_euid);

    msg = (char *)json_object_to_json_string(jobj);
    printf("%s\n", msg);

    return msg;
}

char *handle_PROC_EVENT_GID(struct proc_event *event) {
    // TODO lookup pid exefile/name, hash, ...
    char        *msg;
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
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
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "rgid", j_rgid);
    json_object_object_add(jobj, "egid", j_egid);

    msg = (char *)json_object_to_json_string(jobj);
    printf("%s\n", msg);

    return msg;
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 * pid_t tracer_pid
 * pid_t tracer_tgid
 */
char *handle_PROC_EVENT_PTRACE(struct proc_event *event) {
    // TODO hash of tracer, exefila/name, etc...
    char        *msg;
    json_object *jobj = json_object_new_object();
    json_object *j_timestamp = json_object_new_double(timestamp());
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
    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_pid);
    json_object_object_add(jobj, "tgid", j_tgid);
    json_object_object_add(jobj, "tracer_pid", j_tracer_pid);
    json_object_object_add(jobj, "tracer_tgid", j_tracer_tgid);

    msg = (char *)json_object_to_json_string(jobj);
    printf("%s\n", msg);

    return msg;
}

/* this happens when setsid() happens
 * pid_t process_pid
 * pid_t process_tgid
 */
void handle_PROC_EVENT_SID(struct proc_event *event) {
    return;
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 * char comm[16]
 */
void handle_PROC_EVENT_COMM(struct proc_event *event) {
    return;
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 * pid_t parent_pid
 * pid_t parent_tgid
 */
void handle_PROC_EVENT_COREDUMP(struct proc_event *event) {
    return;
}


void handle_message(struct cn_msg *cn_message) {
    struct proc_event   *event;
    char                *msg;

    event = (struct proc_event *)cn_message->data;

    switch (event->what) {
        case PROC_EVENT_NONE:
            break;

        case PROC_EVENT_FORK:
            msg = handle_PROC_EVENT_FORK(event);
            sockprintf(sock, "%s\r\n", msg);
            break;

        case PROC_EVENT_EXEC:
            msg = handle_PROC_EVENT_EXEC(event);
            sockprintf(sock, "%s\r\n", msg);
            break;

        case PROC_EVENT_EXIT:
            msg = handle_PROC_EVENT_EXIT(event);
            sockprintf(sock, "%s\r\n", msg);
            break;

        case PROC_EVENT_UID:
            msg = handle_PROC_EVENT_UID(event);
            sockprintf(sock, "%s\r\n", msg);
            break;

        case PROC_EVENT_PTRACE:
            msg = handle_PROC_EVENT_UID(event);
            sockprintf(sock, "%s\r\n", msg);
            break;

        case PROC_EVENT_GID:
            msg = handle_PROC_EVENT_GID(event);
            sockprintf(sock, "%s\r\n", msg);
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
}

// TODO clean this up.
int main(int argc, char *argv[]) {
    int                     error;
    int                     netlink;
    struct sockaddr_nl      nl_userland, nl_kernel;
    struct nlmsghdr         *nl_header;
    struct cn_msg           *cn_message;
    char                    buf[1024];
    enum proc_cn_mcast_op   *mcop_msg;

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

    /* create udp socket for sending the logs */
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

    bzero(&s_addr, sizeof(s_addr));;
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    s_addr.sin_port = htons(55555);

    //sendto(sock, "lollol\r\n", 8, 0, (struct sockaddr *)&s_addr, sizeof(s_addr));
    connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr));

    while (1) {
        int                 recv_length;
        socklen_t           nl_kernel_len;
        struct nlmsghdr     *nlh;

        memset(buf, 0x00, sizeof(buf));
        nl_kernel_len = sizeof(nl_kernel);

        recv_length = recvfrom(netlink,
                               buf,
                               sizeof(buf),
                               0,
                               (struct sockaddr *)&nl_kernel,
                               &nl_kernel_len);
        nlh = (struct nlmsghdr *)buf;

        if (recv_length < 1) {
            continue;
        }

        if (nl_kernel.nl_pid != 0) {
            continue;
        }

        while (NLMSG_OK(nlh, recv_length)) {
            cn_message = NLMSG_DATA(nlh);

            if (nlh->nlmsg_type == NLMSG_NOOP) {
                continue;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                break;
            }

            if (nlh->nlmsg_type == NLMSG_OVERRUN) {
                break;
            }

            handle_message(cn_message);

            if (nlh->nlmsg_type == NLMSG_DONE) {
                break;
            } else {
                nlh = NLMSG_NEXT(nlh, recv_length);
            }
        }
    }

    /* Shouldn't ever get here */
    close(netlink);

    return EXIT_SUCCESS;
}

