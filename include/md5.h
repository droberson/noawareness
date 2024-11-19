#pragma once

#define MD5_DIGEST_LENGTH   16
#define MD5_TOO_LARGE       "TOOLARGETOHASH"

char *md5_digest_file(const char *);
