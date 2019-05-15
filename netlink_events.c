#include <stdbool.h>
#include <limits.h>

#include <linux/cn_proc.h>

#include <json-c/json.h>

#include "md5.h"
#include "proc.h"
#include "time_common.h"
#include "string_common.h"

extern char hostname[HOST_NAME_MAX];

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
 * - figure out a better way to hash the exefile. if you run something fast
 *   like 'id' or 'uname -a', handle_PROC_EVENT_EXEC() is not able to get
 *   the hash in time sometimes, resulting in blank fields output. Commenting
 *   this out makes it able to catch the hashes of executed files, which is
 *   probably more important than the forking process in most cases.
 */
char *handle_PROC_EVENT_FORK(struct proc_event *event) {
    char                *exepath;
    bool                deleted;
    //char                *md5;
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
    //json_object         *j_md5;
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
     * % ls /proc/227/exe -l
     * lrwxrwxrwx 1 d d 0 May 12 11:53 /proc/227/exe -> '/home/d/blah (deleted)'
     * % md5sum /proc/227/exe
     * 33d8c8e092458e35ed45a709aa64a99b  /proc/227/exe
     * % md5sum /usr/bin/yes
     * 33d8c8e092458e35ed45a709aa64a99b  /usr/bin/yes
     */
    deleted = endswith(exepath, "(deleted)");
    //md5 = md5_digest_file(proc_exe_path(event->event_data.fork.parent_pid));

    j_exepath     = json_object_new_string(exepath);
    j_deleted     = json_object_new_boolean(deleted);
    j_name        = json_object_new_string(status.name);
    j_uid         = json_object_new_int(status.uid);
    j_euid        = json_object_new_int(status.euid);
    j_gid         = json_object_new_int(status.gid);
    j_egid        = json_object_new_int(status.egid);
    //j_md5         = json_object_new_string(md5);
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
    //json_object_object_add(jobj, "md5", j_md5);
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
    json_object *jobj         = json_object_new_object();
    json_object *j_timestamp  = json_object_new_double(timestamp());
    json_object *j_hostname   = json_object_new_string(hostname);
    json_object *j_pid        = \
      json_object_new_int(event->event_data.exit.process_pid);
    json_object *j_tgid       = \
      json_object_new_int(event->event_data.exit.process_tgid);
    json_object *j_exitcode   = \
      json_object_new_int(event->event_data.exit.exit_code);
    json_object *j_signal     = \
      json_object_new_int(event->event_data.exit.exit_signal);
    json_object *j_event_type = json_object_new_string("exit");

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
    json_object *jobj         = json_object_new_object();
    json_object *j_timestamp  = json_object_new_double(timestamp());
    json_object *j_hostname   = json_object_new_string(hostname);
    json_object *j_pid        = \
      json_object_new_int(event->event_data.id.process_pid);
    json_object *j_tgid       = \
      json_object_new_int(event->event_data.id.process_tgid);
    json_object *j_ruid       = \
      json_object_new_int(event->event_data.id.r.ruid);
    json_object *j_euid       = \
      json_object_new_int(event->event_data.id.e.euid);
    json_object *j_event_type = json_object_new_string("uid");

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