#pragma once

#include <sys/inotify.h>

#define INOTIFY_BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))


typedef struct inotify_entry {
  int wd;
  char filename[INOTIFY_BUF_LEN];
  struct inotify_entry *next;
} inotify_t;


void inotify_add(int, const char *);
void inotify_remove(int);
void inotify_add_files(int, const char *);
void inotify_process_event(int, struct inotify_event *);
