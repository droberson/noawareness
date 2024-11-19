#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "md5/global.h"
#include "md5/md5.h"

#include "base64.h"
#include "md5.h"
#include "error.h"

#undef MD5_SHOW_ERRORS


/* md5_digest_file - Calculate MD5 digest of a file.
 *
 * Args:
 *     path - Path of file to hash.
 *
 * Returns:
 *     string containing the digest on success, "" on failure
 */
char *md5_digest_file(const char *path) {
  unsigned char   c[MD5_DIGEST_LENGTH];
  FILE            *fp;
  int             bytes;
  unsigned char   data[1024 * 64];
  static char     digest[MD5_DIGEST_LENGTH * 2 + 1];
  MD5_CTX         context;

  fp = fopen(path, "rb");
  if (fp == NULL) {
#ifdef MD5_SHOW_ERRORS
    error("md5_digest_file: unable to open %s for reading: %s",
	    path,
	    strerror(errno));
#endif /* MD5_SHOW_ERRORS */
    return "";
  }

  MD5Init(&context);
  while ((bytes = fread(data, 1, sizeof(data), fp)) != 0)
    MD5Update(&context, data, bytes);
  MD5Final(c, &context);

  fclose(fp);

  snprintf(digest, sizeof(digest),
	   "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	   c[0], c[1], c[2], c[3], c[4],
	   c[5], c[6], c[7], c[8], c[9],
	   c[10], c[11], c[12], c[13], c[14],
	   c[15]);

  return digest;
}
