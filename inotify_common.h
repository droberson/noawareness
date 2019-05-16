#pragma once

#define INOTIFY_BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

typedef struct inotify_entry {
  int wd;
  char filename[INOTIFY_BUF_LEN];
  struct inotify_entry *next;
} inotify_t;
