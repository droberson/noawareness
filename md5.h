#pragma once

#define MD5_DIGEST_LENGTH 16

char *md5_digest_file(const char *);
unsigned char *base64_encode(const unsigned char *, size_t, size_t *);
unsigned char *base64_decode(const unsigned char *, size_t, size_t *);
