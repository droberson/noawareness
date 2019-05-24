#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>

extern bool use_syslog;

/* error() - Print messages to stderr.
 *
 * Args:
 *     fmt - Message with format strings.
 *     ... - Optional arguments to fill format strings.
 *
 * Returns:
 *     Nothing.
 */
void error(const char *fmt, ...) {
  char          msg[8192] = {0};
  va_list       vl;

  va_start(vl, fmt);
  vsnprintf(msg, sizeof(msg), fmt, vl);
  va_end(vl);

  fprintf(stderr, "%s\n", msg);

  if (use_syslog)
    syslog(LOG_INFO | LOG_USER, "%s", msg);
}

/* error_fatal() - Print message to stderr and exit with EXIT_FAILURE
 *
 * Args:
 *     fmt - Message with format strings.
 *     ... - Optional arguments to fill format strings.
 *
 * Returns
 *    Nothing, but exits the program with EXIT_FAILURE
 */
void error_fatal(const char *fmt, ...) {
  char          msg[8192] = {0};
  va_list       vl;

  va_start(vl, fmt);
  vsnprintf(msg, sizeof(msg), fmt, vl);
  va_end(vl);

  fprintf(stderr, "%s\n", msg);

  if (use_syslog)
    syslog(LOG_INFO | LOG_USER, "%s", msg);

  exit(EXIT_FAILURE);
}
