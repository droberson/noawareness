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

#include "error.h"
#include "inotify_common.h"


inotify_t       *head = NULL;


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
    error("no inotify config!\n");
    return;
  }

  fp = fopen(path, "r");
  if (fp == NULL)
    error_fatal("Unable to open inotify config file %s: %s\n",
	    path, strerror(errno));

  // TODO add whether to look for just writes, creation, etc in config file.
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    buf[strcspn(buf, "\n")] = '\0';
    if (strlen(buf) == 0)
      continue;

    wd = inotify_add_watch(fd, buf, IN_ALL_EVENTS);
    if (wd == -1)
      error("inotify_add_watch %s: %s\n", buf, strerror(errno));
    else
      inotify_add(wd, buf);
  }

  fclose(fp);
}

void inotify_process_event(int inotify, struct inotify_event *e) {
  int           wd;
  int           found;
  char          output[1024];
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
  char          hashstr[] = "ahashyhashhash";

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
	  error("inotify_add_watch %s: %s\n", path, strerror(errno));
	} else {
	  // TODO print new directory added
	  inotify_add(wd, path);
	}
      }
    }
  } /* if (check_dir) */

  char uid[8];
  char gid[8];
  if (get_perm) {
    if (stat(path, &s) == 0) {
      //pwent = getpwuid(s.st_uid);
      //g = getgrgid(s.st_gid);
      snprintf(uid, sizeof(uid), "%d", s.st_uid);
      snprintf(gid, sizeof(gid), "%d", s.st_gid);
      snprintf(permstr, sizeof(permstr), "%o", s.st_mode);
    }
  }

  //if (hash)
    // TODO if file is over X bytes, dont hash
    // do hash

   snprintf(output, sizeof(output), "%s; wd =%2d; %s%s%s%s%s%s%s%s%s%s%s%s",
	    path,
	    e->wd,
	    (e->cookie > 0) ? "cookie =" : "",
	    (e->cookie > 0) ? int2str : "",
	    (e->cookie > 0) ? "; " : "",
	    mask,
	    get_perm || hash ? "; " : "",
	    get_perm || hash ? uid : "",
	    //get_perm || hash ? pwent->pw_name : "",
	    get_perm || hash ? ":" : "",
	    get_perm || hash ? gid : "",
	    //get_perm || hash ? g->gr_name : "",
	    get_perm ? "; perm = " : "",
	    get_perm ? permstr : "",
	    hash ? " ; hash = " : "",
	    hash ? hashstr : "");
   printf("%s\n", output);
}
