#include "util.h"
#include "../asconhashav12/hash.c"


int encodeBN(BIGNUM* bn, uint8_t** p, size_t* plen)
{
    *plen = BN_num_bytes(bn);
    *p = new uint8_t[*plen];

    BN_bn2bin(bn, *p);

    return 1;
}

int ascon_hash(uint8_t* hash, uint8_t* message, size_t messagelen)
{

    if (0 != crypto_hash(hash, message, messagelen))                                    { return 1; }

    return 0;
}

int concat_str_str(uint8_t* msg1, size_t msglen1,
                   uint8_t* msg2, size_t msglen2,
                   uint8_t* res, size_t *reslen)
{
    *reslen = msglen1 + msglen2;
    memcpy(res, msg1, msglen1);
    memcpy(res + msglen1, msg2, msglen2);

    return 1;
}
