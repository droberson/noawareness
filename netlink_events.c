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
 * TODO: Deal with parent_pid and child_pid being the same somehow (see below)
 */
char *handle_PROC_EVENT_FORK(struct proc_event *event) {
  pid_t               parent_pid     = event->event_data.fork.parent_pid;
  char                *exepath       = proc_get_exe_path(parent_pid);
  bool                deleted;
  char                *md5;
  struct proc_status  status;
  json_object         *jobj          = json_object_new_object();
  json_object         *j_md5;
  json_object         *j_deleted;
  json_object         *j_timestamp   = json_object_new_double(timestamp());
  json_object         *j_hostname    = json_object_new_string(hostname);
  json_object         *j_exepath     = json_object_new_string(exepath);
  json_object         *j_name        = json_object_new_string(status.name);
  json_object         *j_uid         = json_object_new_int(status.uid);
  json_object         *j_euid        = json_object_new_int(status.euid);
  json_object         *j_gid         = json_object_new_int(status.gid);
  json_object         *j_egid        = json_object_new_int(status.egid);
  json_object         *j_parent_pid  = json_object_new_int(parent_pid);
  json_object         *j_parent_tgid = \
    json_object_new_int(event->event_data.fork.parent_tgid);
  json_object         *j_child_pid   = \
    json_object_new_int(event->event_data.fork.child_pid);
  json_object         *j_child_tgid  = \
    json_object_new_int(event->event_data.fork.child_tgid);
  json_object         *j_cmdline;
  json_object         *j_event_type  = json_object_new_string("fork");

  /* Do this before anything to have better chances of catching the hash */
  md5 = md5_digest_file(proc_exe_path(parent_pid));
  j_md5 = json_object_new_string(md5);

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
  j_deleted = json_object_new_boolean(deleted);

  /* Do this after hashing md5, so we have a better chance of catching
   * the process before it is closed.
   */
  status = proc_get_status(parent_pid);
  j_cmdline = json_object_new_string(proc_get_cmdline(parent_pid));

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
  // Parent and child are same data when this event is caught.
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
  pid_t                 pid = event->event_data.exec.process_pid;
  char                  *exefile = proc_get_exe_path(pid);
  struct proc_status    procstatus;
  json_object           *jobj = json_object_new_object();
  json_object           *j_timestamp = json_object_new_double(timestamp());
  json_object           *j_hostname = json_object_new_string(hostname);
  json_object           *j_exepath;
  json_object           *j_process_pid = json_object_new_int(pid);
  json_object           *j_process_tgid = \
    json_object_new_int(event->event_data.exec.process_tgid);
  json_object           *j_md5;
  json_object           *j_cmdline;
  json_object           *j_cwd;
  json_object           *j_uid, *j_euid;
  json_object           *j_gid, *j_egid;
  json_object           *j_event_type = json_object_new_string("exec");

  j_md5          = json_object_new_string(md5_digest_file(exefile));
  j_exepath      = json_object_new_string(exefile);
  j_cmdline      = json_object_new_string(proc_get_cmdline(pid));
  j_cwd          = json_object_new_string(proc_cwd(pid));
  procstatus     = proc_get_status(pid);
  j_uid          = json_object_new_int(procstatus.uid);
  j_euid         = json_object_new_int(procstatus.euid);
  j_gid          = json_object_new_int(procstatus.gid);
  j_egid         = json_object_new_int(procstatus.egid);

  json_object_object_add(jobj, "timestamp", j_timestamp);
  json_object_object_add(jobj, "hostname", j_hostname);
  json_object_object_add(jobj, "event_type", j_event_type);
  json_object_object_add(jobj, "pid", j_process_pid);
  json_object_object_add(jobj, "tgid", j_process_tgid);
  json_object_object_add(jobj, "uid", j_uid);
  json_object_object_add(jobj, "euid", j_euid);
  json_object_object_add(jobj, "gid", j_gid);
  json_object_object_add(jobj, "egid", j_egid);
  json_object_object_add(jobj, "md5", j_md5);
  json_object_object_add(jobj, "exepath", j_exepath);
  json_object_object_add(jobj, "cmdline", j_cmdline);
  json_object_object_add(jobj, "cwd", j_cwd);

  return (char *)json_object_to_json_string(jobj);
}

/* handle_PROC_EVENT_EXEC_environment() - Grab the environment from
 * PROC_EVENT_EXEC events.
 *
 * This is called after handle_PROC_EVENT_EXEC() to attempt to grab
 * the environment from /proc/X/environ for a newly-executed
 * process. This information may be useful from a forensics
 * standpoint, and possibly to detect malicious activity.
 *
 * Since an environment can contain anything, it is base64 encoded so
 * it doesn't break our JSON formatting.
 *
 * Args:
 *     event - proc_event structure (linux/cn_proc.h)
 *
 * Returns:
 *     char * containing serialized JSON object describing this event.
 */
char *handle_PROC_EVENT_EXEC_environment(struct proc_event *event) {
  // TODO what happens when you pass a very large environment?
  pid_t                 pid = event->event_data.exec.process_pid;
  char                  *exefile = proc_get_exe_path(pid);
  struct proc_status    procstatus;
  json_object           *jobj = json_object_new_object();
  json_object           *j_timestamp   = json_object_new_double(timestamp());
  json_object           *j_hostname    = json_object_new_string(hostname);
  json_object           *j_exepath     = json_object_new_string(exefile);
  json_object           *j_pid         = json_object_new_int(pid);
  json_object           *j_uid, *j_euid;
  json_object           *j_gid, *j_egid;
  json_object           *j_event_type  = json_object_new_string("environment");
  json_object           *j_environment = \
    json_object_new_string(proc_environ(pid));

  procstatus = proc_get_status(pid);
  j_uid = json_object_new_int(procstatus.uid);
  j_euid = json_object_new_int(procstatus.euid);
  j_gid = json_object_new_int(procstatus.gid);
  j_egid = json_object_new_int(procstatus.egid);

  json_object_object_add(jobj, "timestamp", j_timestamp);
  json_object_object_add(jobj, "hostname", j_hostname);
  json_object_object_add(jobj, "event_type", j_event_type);
  json_object_object_add(jobj, "pid", j_pid);
  json_object_object_add(jobj, "uid", j_uid);
  json_object_object_add(jobj, "euid", j_euid);
  json_object_object_add(jobj, "gid", j_gid);
  json_object_object_add(jobj, "egid", j_egid);
  json_object_object_add(jobj, "exepath", j_exepath);
  json_object_object_add(jobj, "environment", j_environment);

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
  json_object *j_pid        =					\
    json_object_new_int(event->event_data.exit.process_pid);
  json_object *j_tgid       =					\
    json_object_new_int(event->event_data.exit.process_tgid);
  json_object *j_exitcode   =					\
    json_object_new_int(event->event_data.exit.exit_code);
  json_object *j_signal     =					\
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
  pid_t       pid           = event->event_data.id.process_pid;
  char        *exefile      = proc_get_exe_path(pid);
  json_object *jobj         = json_object_new_object();
  json_object *j_timestamp  = json_object_new_double(timestamp());
  json_object *j_hostname   = json_object_new_string(hostname);
  json_object *j_exepath    = json_object_new_string(exefile);
  json_object *j_pid        = json_object_new_int(pid);
  json_object *j_tgid       = \
    json_object_new_int(event->event_data.id.process_tgid);
  json_object *j_ruid       = json_object_new_int(event->event_data.id.r.ruid);
  json_object *j_euid       = json_object_new_int(event->event_data.id.e.euid);
  json_object *j_event_type = json_object_new_string("uid");

  json_object_object_add(jobj, "timestamp", j_timestamp);
  json_object_object_add(jobj, "hostname", j_hostname);
  json_object_object_add(jobj, "event_type", j_event_type);
  json_object_object_add(jobj, "exepath", j_exepath);
  json_object_object_add(jobj, "pid", j_pid);
  json_object_object_add(jobj, "tgid", j_tgid);
  json_object_object_add(jobj, "ruid", j_ruid);
  json_object_object_add(jobj, "euid", j_euid);

  return (char *)json_object_to_json_string(jobj);
}

char *handle_PROC_EVENT_GID(struct proc_event *event) {
  pid_t       pid           = event->event_data.id.process_pid;
  char        *exefile      = proc_get_exe_path(pid);
  json_object *jobj         = json_object_new_object();
  json_object *j_timestamp  = json_object_new_double(timestamp());
  json_object *j_hostname   = json_object_new_string(hostname);
  json_object *j_exepath    = json_object_new_string(exefile);
  json_object *j_pid        = json_object_new_int(pid);
  json_object *j_tgid       = \
    json_object_new_int(event->event_data.id.process_tgid);
  json_object *j_rgid       = json_object_new_int(event->event_data.id.r.rgid);
  json_object *j_egid       = json_object_new_int(event->event_data.id.e.egid);
  json_object *j_event_type = json_object_new_string("gid");

  json_object_object_add(jobj, "timestamp", j_timestamp);
  json_object_object_add(jobj, "hostname", j_hostname);
  json_object_object_add(jobj, "event_type", j_event_type);
  json_object_object_add(jobj, "exepath", j_exepath);
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
 *     This appears to be called AFTER ptrace() calls, so obtaining the
 *     path, hash, etc of the tracer process may fail sometimes.
 */
char *handle_PROC_EVENT_PTRACE(struct proc_event *event) {
  json_object *jobj = json_object_new_object();
  char        *targetpath    = \
    proc_get_exe_path(event->event_data.ptrace.process_pid);
  char        *tracerpath    = \
    proc_get_exe_path(event->event_data.ptrace.tracer_pid);

  json_object *j_timestamp   = json_object_new_double(timestamp());
  json_object *j_hostname    = json_object_new_string(hostname);
  json_object *j_pid         = \
    json_object_new_int(event->event_data.ptrace.process_pid);
  json_object *j_tgid        = \
    json_object_new_int(event->event_data.ptrace.process_tgid);
  json_object *j_tracer_pid  = \
    json_object_new_int(event->event_data.ptrace.tracer_pid);
  json_object *j_tracer_tgid = \
    json_object_new_int(event->event_data.ptrace.tracer_tgid);
  json_object *j_tracer_path = json_object_new_string(tracerpath);
  json_object *j_target_path = json_object_new_string(targetpath);
  json_object *j_event_type  = json_object_new_string("ptrace");

  json_object_object_add(jobj, "timestamp", j_timestamp);
  json_object_object_add(jobj, "hostname", j_hostname);
  json_object_object_add(jobj, "event_type", j_event_type);
  json_object_object_add(jobj, "pid", j_pid);
  json_object_object_add(jobj, "tgid", j_tgid);
  json_object_object_add(jobj, "tracer_pid", j_tracer_pid);
  json_object_object_add(jobj, "tracer_tgid", j_tracer_tgid);
  json_object_object_add(jobj, "tracer_path", j_tracer_path);
  json_object_object_add(jobj, "target_path", j_target_path);

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
