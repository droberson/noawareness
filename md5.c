#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/md5.h>

#include "md5.h"
#include "error.h"

#undef MD5_SHOW_ERRORS


// Stole from Jouni Malinen <j@w1.fi>
unsigned char *base64_encode(const unsigned char *src, size_t len, size_t *out_len) {
  const unsigned char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  unsigned char *out, *pos;
  const unsigned char *end, *in;
  size_t olen;

  olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
  olen += olen / 72; /* line feeds */
  olen++; /* nul termination */
  if (olen < len)
    return NULL; /* integer overflow */
  out = malloc(olen);
  if (out == NULL)
    return NULL;

  end = src + len;
  in = src;
  pos = out;

  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4) |
			    (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
  }

  *pos = '\0';
  if (out_len)
    *out_len = pos - out;

  return out;
}

// Stole from Jouni Malinen <j@w1.fi>
unsigned char *base64_decode(const unsigned char *src, size_t len, size_t *out_len) {
  const unsigned char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  unsigned char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (unsigned char) i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[src[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3;
  pos = out = malloc(olen);
  if (out == NULL)
    return NULL;

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[src[i]];
    if (tmp == 0x80)
      continue;

    if (src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
	if (pad == 1)
	  pos--;
	else if (pad == 2)
	  pos -= 2;
	else {
	  /* Invalid padding */
	  free(out);
	  return NULL;
	}
	break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}

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
  unsigned char   data[8192];
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

  MD5_Init(&context);
  while ((bytes = fread(data, 1, sizeof(data), fp)) != 0)
    MD5_Update(&context, data, bytes);
  MD5_Final(c, &context);

  fclose(fp);

  snprintf(digest, sizeof(digest),
	   "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	   c[0], c[1], c[2], c[3], c[4],
	   c[5], c[6], c[7], c[8], c[9],
	   c[10], c[11], c[12], c[13], c[14],
	   c[15]);

  return digest;
}
