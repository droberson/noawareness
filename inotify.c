#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>

#include <json-c/json.h>

#include "error.h"
#include "net.h"
#include "md5.h"
#include "inotify_common.h"
#include "time_common.h"


inotify_t               *head = NULL;
extern char             hostname[HOST_NAME_MAX];
extern sock_t           sock;
extern bool             daemonize;
extern bool             remote_logging;
extern bool             quiet;
extern unsigned long    maxsize;

void inotify_add(int wd, const char *filename) {
  inotify_t	*link = (inotify_t *)malloc(sizeof(inotify_t));

  link->wd = wd;
  strncpy(link->filename, filename, sizeof(link->filename));

  link->next = head;
  head = link;
}

void inotify_remove(int wd) {
  inotify_t     *search;
  inotify_t     *match;

  search = head;

  if (search->wd == wd) {
    head = search->next;
    free(search);
    return;
  }

  while (search->next) {
    if (search->next->wd == wd) {
      match = search->next;

      search->next = search->next->next;
      free(match);

      break;
    }

    search = search->next;
  }
}

void inotify_add_files(int fd, const char *path) {
  int	wd;
  FILE  *fp;
  char  buf[INOTIFY_BUF_LEN];

  // TODO add some sane defaults to this if no config file
  // - /etc
  // - /tmp, /var/tmp, /dev/shm
  // - /root
  // - /var/www/
  if (path == NULL) {
    error("no inotify config provided!");
    return;
  }

  fp = fopen(path, "r");
  if (fp == NULL)
    error_fatal("Unable to open inotify config file %s: %s",
	    path, strerror(errno));

  // TODO add whether to look for just writes, creation, etc in config file.
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    buf[strcspn(buf, "\n")] = '\0';
    if (strlen(buf) == 0)
      continue;

    wd = inotify_add_watch(fd, buf, IN_ALL_EVENTS);
    if (wd == -1)
      error("inotify_add_watch %s: %s", buf, strerror(errno));
    else
      inotify_add(wd, buf);
  }

  fclose(fp);
}

void inotify_process_event(int inotify, struct inotify_event *e) {
  int           wd;
  int           found;
  char          int2str[32];
  char          *mask;
  char          path[PATH_MAX];
  char          permstr[8];
  inotify_t     *current = head;
  inotify_t     *search;
  bool          hash      = false,
                get_perm  = false,
                check_dir = false,
                remove    = false;
  struct stat   s;
  //struct passwd *pwent;
  //struct group  *g;
  char          *md5;

  while (current->wd != e->wd)
    current = current->next;

  if (e->mask & IN_ACCESS)          mask = "IN_ACCESS";
  if (e->mask & IN_ATTRIB)        { mask = "IN_ATTRIB"; get_perm = true; }
  if (e->mask & IN_CLOSE_NOWRITE)   mask = "IN_CLOSE_NOWRITE";
  if (e->mask & IN_CLOSE_WRITE)   { mask = "IN_CLOSE_WRITE"; hash = true; }
  if (e->mask & IN_CREATE)        { mask = "IN_CREATE"; get_perm = true; }
  if (e->mask & IN_DELETE)          mask = "IN_DELETE";
  if (e->mask & IN_DELETE_SELF)     mask = "IN_DELETE_SELF";
  if (e->mask & IN_IGNORED)       { mask = "IN_IGNORED"; remove = true; }
  if (e->mask & IN_ISDIR)         { mask = "IN_ISDIR"; check_dir = true; }
  if (e->mask & IN_MODIFY)        { mask = "IN_MODIFY"; hash = true; }
  if (e->mask & IN_MOVE_SELF)       mask = "IN_MOVE_SELF";
  if (e->mask & IN_MOVED_FROM)      mask = "IN_MOVED_FROM";
  if (e->mask & IN_MOVED_TO)        mask = "IN_MOVED_TO";
  if (e->mask & IN_OPEN)          { mask = "IN_OPEN"; get_perm = true; }
  if (e->mask & IN_Q_OVERFLOW)      mask = "IN_Q_OVERFLOW";
  if (e->mask & IN_UNMOUNT)         mask = "IN_UNMOUNT";

  if (e->cookie > 0)
    snprintf(int2str, sizeof(int2str), "%4d", e->cookie);

  snprintf(path, sizeof(path), "%s%s%s",
	   current->filename,
	   (e->len > 0) ? "/" : "",
	   (e->len > 0) ? e->name : "");

  if (remove)
    inotify_remove(e->wd);

  if (check_dir) {
    search = head;

    for (found = 0; search->next; search = search->next) {
      if (strcmp(search->filename, path) == 0) {
	found = search->wd;
	break;
      }
    }

    if (found == 0) {
      if (stat(path, &s) == 0) {
	wd = inotify_add_watch(inotify, path, IN_ALL_EVENTS);
	if (wd == -1) {
	  error("inotify_add_watch %s: %s", path, strerror(errno));
	} else {
	  // TODO print new directory added
	  inotify_add(wd, path);
	}
      }
    }
  } /* if (check_dir) */

  if (get_perm) { // TODO deal with errors
    if (stat(path, &s) == 0)
      snprintf(permstr, sizeof(permstr), "%o", s.st_mode);
  }

  if (hash) {
    if (s.st_size < maxsize)
      md5 = md5_digest_file(path);
    else
      md5 = "TOOLARGETOHASH";
  }

  json_object *jobj           = json_object_new_object();
  json_object *j_timestamp    = json_object_new_double(timestamp());
  json_object *j_hostname     = json_object_new_string(hostname);
  json_object *j_event_type   = json_object_new_string("inotify");
  json_object *j_inotify_mask = json_object_new_string(mask);
  json_object *j_path         = json_object_new_string(path);
  json_object *j_uid;
  json_object *j_gid;
  json_object *j_perm;
  json_object *j_size;
  json_object *j_md5;

  json_object_object_add(jobj, "timestamp", j_timestamp);
  json_object_object_add(jobj, "hostname", j_hostname);
  json_object_object_add(jobj, "event_type", j_event_type);
  json_object_object_add(jobj, "inotify_mask", j_inotify_mask);
  json_object_object_add(jobj, "path", j_path);

  if (get_perm) {
    j_uid  = json_object_new_int(s.st_uid);
    j_gid  = json_object_new_int(s.st_gid);
    j_perm = json_object_new_string(permstr);
    j_size = json_object_new_int(s.st_size);

    json_object_object_add(jobj, "uid", j_uid);
    json_object_object_add(jobj, "gid", j_gid);
    json_object_object_add(jobj, "permissions", j_perm);
    json_object_object_add(jobj, "size", j_size);
  }

  if (hash) {
    j_md5 = json_object_new_string(md5);
    json_object_object_add(jobj, "md5", j_md5);
  }

  char *msg = (char *)json_object_to_json_string(jobj);
  // TODO reuse output()
  if (!daemonize)
    if (!quiet)
      printf("%s\n", msg);
  if (remote_logging)
    sockprintf(sock, "%s\r\n", msg);
}
