#pragma once

void handle_PROC_EVENT_SID(struct proc_event *);
void handle_PROC_EVENT_COMM(struct proc_event *);
void handle_PROC_EVENT_COREDUMP(struct proc_event *);
char *handle_PROC_EVENT_FORK(struct proc_event *);
char *handle_PROC_EVENT_EXEC(struct proc_event *);
char *handle_PROC_EVENT_EXEC_environment(struct proc_event *);
char *handle_PROC_EVENT_EXIT(struct proc_event *);
char *handle_PROC_EVENT_UID(struct proc_event *);
char *handle_PROC_EVENT_GID(struct proc_event *);
char *handle_PROC_EVENT_PTRACE(struct proc_event *);
