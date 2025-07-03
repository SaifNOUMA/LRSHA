#ifndef SIGN_H
#define SIGN_H

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
    BIGNUM          *y, *r;
    uint8_t         r1[32], r2[32], r3[32], x[32], y1[32], y2[32], y3[32];

    int update_keys();
    int compute_sk();
    int compute_r();

public:
    Signer(int id);
    ~Signer();

    int setSignerKeys(EC_GROUP *ec_group,
                      uint8_t *y1, size_t y1len,
                      uint8_t *y2, size_t y2len,
                      uint8_t *y3, size_t y3len,
                      uint8_t *r1_arg, size_t r1len_arg,
                      uint8_t *r2_arg, size_t r2len_arg,
                      uint8_t *r3_arg, size_t r3len_arg);

    int sign_message(uint8_t* message, size_t messagelen,
                     struct sig *signature,
                     double *r_comp, double *x_comp, double *sk_comp, double *sk_upd, double *sgn_comp);

    int send_signature(unsigned char* sig, size_t siglen);


    EC_POINT*       Y;
    EC_GROUP*       ec_group;
};

#endif
