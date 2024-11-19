/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE    32            // SHA256 outputs a 32 byte digest
#define SHA256_DIGEST_LENGTH SHA256_BLOCK_SIZE
#define SHA256_TOO_LARGE     "TOOLARGETOHASH"

#undef SHA256_SHOW_ERRORS // for debugging

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *);
void sha256_update(SHA256_CTX *, const BYTE [], size_t);
void sha256_final(SHA256_CTX *, BYTE []);
char *sha256_digest_file(const char *);
#endif   // SHA256_H
