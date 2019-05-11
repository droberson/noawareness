#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>


int sockprintf(int s, const char *fmt, ...) {
    int     n;
    char    buf[8192];
    va_list vl;

    memset(buf, 0x00, sizeof(buf));

    va_start(vl, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, vl);
    va_end(vl);

    return send(s, buf, n, 0);
}
