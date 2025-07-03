#ifndef CONF_H
#define CONF_H

#include "string.h"
#include "math.h"
#include "string.h"
#include "stdlib.h"
#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <sgx_urts.h>
#include <openssl/sha.h>

# define MAX_PATH FILENAME_MAX

#define EC_POINT_SIZE 32
#define HASH_SIZE 32

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "Enclave.signed.so"


struct sig
{
    uint8_t s[32];
    uint8_t x[32];
    size_t  counter;
};

#endif
