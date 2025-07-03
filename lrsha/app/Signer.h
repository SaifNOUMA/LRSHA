
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "util.h"
#include "conf.h"

class Signer
{
private:
    int             ID;
    size_t          counter;
    BIGNUM          *y;
    uint8_t         r1[32], r2[32], r3[32], x[32];

public:
    Signer(int id);
    ~Signer();

    int setSignerKeys(EC_GROUP *ec_group,
                      uint8_t *y, size_t ylen,
                      uint8_t *r1_arg, size_t r1len_arg,
                      uint8_t *r2_arg, size_t r2len_arg,
                      uint8_t *r3_arg, size_t r3len_arg);

    int sign_message(uint8_t* message, size_t messagelen,
                     struct sig *signature,
                     double *sk_comp, double *sgn_comp);

    int send_signature(unsigned char* sig, size_t siglen);


    EC_POINT*       Y;
    EC_GROUP*       ec_group;
};
