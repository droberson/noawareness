#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "md5_common.h"
#include "proc_common.h"
#include "string_common.h"

// TODO keep track of processes as they are executed to give EXIT better context
// TODO deal with (deleted) files as exefile
    // TODO read /proc/X/maps, get actual map's md5sum. this should work if
    // the (deleted) suffix in exepath is there
// TODO remote logging json
// TODO daemonize
    // TODO pid file + watchdog script
// TODO entropy of file.
// TODO environment?? /proc/X/environ
// TODO limits? /proc/X/limits

// TODO add inotify-watch stuff
    // writes to passwd, shadow, sudoers, sudoers.d, ...

// https://www.kernel.org/doc/Documentation/connector/connector.txt

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
void handle_PROC_EVENT_FORK(struct proc_event *event) {
    char                *exepath;
    struct proc_status  status;

    status = proc_get_status(event->event_data.fork.parent_pid);
    exepath = proc_get_exe_path(event->event_data.fork.parent_pid);

    printf("FORK %s\n"
           "\tuid=%d\n"
           "\teuid=%d\n"
           "\tgid=%d\n"
           "\tegid=%d\n"
           "\tmd5=%s\n"
           "\tparent(pid,tgid)=%d,%d\n"
           "\tchild(pid,tgid)=%d,%d\n"
           "\texepath=%s\n"
           "\tcmdline=%s\n",
           status.name,
           status.uid,
           status.euid,
           status.gid,
           status.egid,
           md5_digest_file(exepath),
           event->event_data.fork.parent_pid,
           event->event_data.fork.parent_tgid,
           event->event_data.fork.child_pid,
           event->event_data.fork.child_tgid,
	   exepath,
	   proc_get_cmdline(event->event_data.fork.parent_pid));
     // TODO this only shows the parent, until child exec()s; this ends up
     // showing the same pids for parent and child..
     //printf("%s %s\n", proc_get_exe_path(event->event_data.fork.parent_pid),
	//	       proc_get_cmdline(event->event_data.fork.child_pid));
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 */
void handle_PROC_EVENT_EXEC(struct proc_event *event) {
    //TODO add timestamp
    char        *exefile;
    json_object *jobj = json_object_new_object();
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

    json_object_object_add(jobj, "event_type", j_event_type);
    json_object_object_add(jobj, "pid", j_process_pid);
    json_object_object_add(jobj, "tgid", j_process_tgid);
    json_object_object_add(jobj, "md5", j_md5);
    json_object_object_add(jobj, "exename", j_exepath);
    json_object_object_add(jobj, "cmdline", j_cmdline);

    printf("%s\n", json_object_to_json_string(jobj));
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 * u32 exit_code
 * u32 exit_signal
 * pid_t parent_pid
 * pid_t parent_tgid
 */
void handle_PROC_EVENT_EXIT(struct proc_event *event) {
    printf("EXIT pid=%d tgid=%d exitcode=%d signal=%d\n",
           event->event_data.exit.process_pid,
           event->event_data.exit.process_tgid,
           event->event_data.exit.exit_code,
           event->event_data.exit.exit_signal);
}

/*
 * pid_t process_ppid
 * pid_t process_tgid
 * union { u32 ruid; u32 rgid } r
 * union { u32 euid; u32 egid } e
 */
void handle_PROC_EVENT_UID(struct proc_event *event) {
    printf("UID pid=%d tgid=%d ruid=%d euid=%d\n",
        event->event_data.id.process_pid,
        event->event_data.id.process_tgid,
        event->event_data.id.r.ruid,
        event->event_data.id.e.euid);
}

void handle_PROC_EVENT_GID(struct proc_event *event) {
    printf("GID pid=%d tgid=%d rgid=%d egid=%d\n",
        event->event_data.id.process_pid,
        event->event_data.id.process_tgid,
        event->event_data.id.r.rgid,
        event->event_data.id.e.egid);
}

/*
 * pid_t process_pid
 * pid_t process_tgid
 * pid_t tracer_pid
 * pid_t tracer_tgid
 */
void handle_PROC_EVENT_PTRACE(struct proc_event *event) {
    printf("PTRACE pid=%d tgid=%d tracer_pid=%d tracer_tgid=%d\n",
        event->event_data.ptrace.process_pid,
        event->event_data.ptrace.process_tgid,
        event->event_data.ptrace.tracer_pid,
        event->event_data.ptrace.tracer_tgid);
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

    event = (struct proc_event *)cn_message->data;

    switch (event->what) {
        case PROC_EVENT_NONE:
            break;

        case PROC_EVENT_FORK:
            handle_PROC_EVENT_FORK(event);
            break;

        case PROC_EVENT_EXEC:
            handle_PROC_EVENT_EXEC(event);
            break;

        case PROC_EVENT_EXIT:
            handle_PROC_EVENT_EXIT(event);
            break;

        case PROC_EVENT_UID:
            handle_PROC_EVENT_UID(event);
            break;

        case PROC_EVENT_PTRACE:
            handle_PROC_EVENT_UID(event);
            break;

        case PROC_EVENT_GID:
            handle_PROC_EVENT_GID(event);
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

int main(int argc, char *argv[]) {
    int                     error;
    int                     netlink;
    struct sockaddr_nl      nl_userland, nl_kernel;
    struct nlmsghdr         *nl_header;
    struct cn_msg           *cn_message;
    char                    buf[1024];


    /* Create netlink socket */
    netlink = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (netlink == -1) {
        fprintf(stderr,
            "error creating netlink socket: %s\n",
            strerror(errno));
        return EXIT_FAILURE;
    }

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

    close(netlink);

    return EXIT_SUCCESS;
}

