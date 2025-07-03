#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

int encodeBN(BIGNUM* bn, uint8_t** p, size_t* plen);

int ascon_hash(uint8_t* hash, uint8_t* message, size_t messagelen);

int concat_str_str(uint8_t* msg1, size_t msglen1,
                   uint8_t* msg2, size_t msglen2,
                   uint8_t* res, size_t *reslen);

#endif
