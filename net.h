#pragma once

typedef int             sock_t;
typedef unsigned short  port_t;

int sockprintf(int, const char *, ...);
bool validate_ipv4(const char *);
