#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void error(const char *fmt, ...) {
  va_list       vl;

  va_start(vl, fmt);
  vfprintf(stderr, fmt, vl);
  va_end(vl);
}

void error_fatal(const char *fmt, ...) {
  va_list       vl;

  va_start(vl, fmt);
  vfprintf(stderr, fmt, vl);
  va_end(vl);

  exit(EXIT_FAILURE);
}
