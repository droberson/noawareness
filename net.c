#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


int sockprintf(int s, const char *fmt, ...) {
	int     n;
	char    buf[8192] = {0};
	va_list vl;

	va_start(vl, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	return send(s, buf, n, 0);
}

bool validate_ipv4(const char *ip) {
	return inet_aton(ip, NULL) ? true : false;
}

bool validate_ip(const char *ip) {
	struct in_addr  addr4;
	struct in6_addr addr6;

	return inet_pton(AF_INET, ip, &addr4) == 1 || inet_pton(AF_INET6, ip, &addr6) == 1;
}
