#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

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
  va_list       vl;

  va_start(vl, fmt);
  vfprintf(stderr, fmt, vl);
  va_end(vl);
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
  va_list       vl;

  va_start(vl, fmt);
  vfprintf(stderr, fmt, vl);
  va_end(vl);

  exit(EXIT_FAILURE);
}
