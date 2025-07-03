/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "../asconhashav12/hash.c"
#include "Enclave.h"
#include "Enclave_t.h"
#include "tSgxSSL_api.h"
#define ADD_ENTROPY_SIZE	32


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

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_uprint(buf);
}


int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
	char buf[BUFSIZ] = {'\0'};

	int res = vsnprintf(buf, BUFSIZ, fmt, arg);
	if (res >=0) {
		sgx_status_t sgx_ret = ocall_uprint((const char *) buf);
		TEST_CHECK(sgx_ret);
	}
	return res;
}

/**
 * Function Name: send_dp
 *
 * Description:
 * Send the EC domain parameters
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void send_dp(uint8_t* p, size_t plen,
             uint8_t* a, size_t alen,
             uint8_t* b, size_t blen,
             uint8_t* gx, size_t gxlen,
             uint8_t* gy, size_t gylen,
             uint8_t* order, size_t orderlen,
             uint8_t* cofactor, size_t cofactorlen)
{
    BIGNUM      *p_nb, *a_nb, *b_nb, *cofactor_bn, *gx_bn, *gy_bn;
    EC_POINT    *generator;

    p_nb            = BN_bin2bn(p, plen, NULL);
    a_nb            = BN_bin2bn(a, alen, NULL);
    b_nb            = BN_bin2bn(b, blen, NULL);
    gx_bn           = BN_bin2bn(gx, gxlen, NULL);
    gy_bn           = BN_bin2bn(gy, gylen, NULL);
    order_bn        = BN_bin2bn(order, orderlen, NULL);
    cofactor_bn     = BN_bin2bn(cofactor, cofactorlen, NULL);

    if (p_nb == NULL || a_nb == NULL || b_nb == NULL || cofactor_bn == NULL)                        { return; }
    
    ec_group = EC_GROUP_new_curve_GFp(p_nb, a_nb, b_nb, NULL);
    if (ec_group == NULL)                                                                           { return; }

    generator = EC_POINT_new(ec_group);
    if (generator == NULL)                                                                          { return; }
    if (0 == EC_POINT_set_affine_coordinates(ec_group, generator, gx_bn, gy_bn, NULL))              { return; }
    if (0 == EC_GROUP_set_generator(ec_group, generator, order_bn, cofactor_bn))                    { return; }

}


/**
 * Function Name: send_msk
 *
 * Description:
 * Send authority master key
 * @param key: the master key
 * @param keylen: length of master key
 *
 * @return NULL
 */
void send_comm(unsigned char* r1_a, size_t r1_a_len,
               unsigned char* r2_a, size_t r2_a_len,
               unsigned char* r3_a, size_t r3_a_len,
               unsigned char* y1_a, size_t y1_a_len,
               unsigned char* y2_a, size_t y2_a_len,
               unsigned char* y3_a, size_t y3_a_len)
{

    memcpy(r1, r1_a, r1_a_len);
    memcpy(r2, r2_a, r2_a_len);
    memcpy(r3, r3_a, r3_a_len);

    memcpy(y1, y1_a, y1_a_len);
    memcpy(y2, y2_a, y2_a_len);
    memcpy(y3, y3_a, y3_a_len);

}


/**
 * Function Name: request_PK1
 *
 * Description:
 * Get the public key (EC point) Yj from the enclave
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void request_PK1(uint8_t Y1[256], size_t* Y1len,
                 uint8_t R1[256], size_t* R1len,
                 size_t counter)
{
    uint8_t     *R_tmp, *Y_tmp,
                y1j[32], r1j[32];
    BN_CTX      *bn_ctx;
    BIGNUM      *r1_bn, *y1_bn;
    EC_POINT    *R1_point, *Y1_point;


    Y1_point = EC_POINT_new(ec_group);
    R1_point = EC_POINT_new(ec_group);
    bn_ctx   = BN_CTX_new();
    r1_bn    = BN_new();
    y1_bn    = BN_new();

    memcpy(y1j, y1, 32);
    for (int i = 0 ; i < counter ; i++) {
        if (0 != ascon_hash(y1j, y1j, 32))                                                          { return; }
    }

    memcpy(r1j, r1, 32);
    for (int i = 0 ; i < counter ; i++) {
        if (0 != ascon_hash(r1j, r1j, 32))                                                          { return; }
    }

    if (NULL == (y1_bn = BN_bin2bn(y1j, 32, 0)))                                                    { return; }   
    if (NULL == (r1_bn = BN_bin2bn(r1j, 32, 0)))                                                    { return; }

    if (0 == BN_mod(y1_bn, y1_bn, order_bn, bn_ctx))                                                { return; }   /* y1 = y1 mod q */
    if (0 == BN_mod(r1_bn, r1_bn, order_bn, bn_ctx))                                                { return; }   /* r1 = r1 mod q */

    if (0 == EC_POINT_mul(ec_group, Y1_point, y1_bn, NULL, NULL, NULL))                             { return; }
    if (0 == EC_POINT_mul(ec_group, R1_point, r1_bn, NULL, NULL, NULL))                             { return; }

    *Y1len = EC_POINT_point2buf(ec_group, Y1_point, POINT_CONVERSION_UNCOMPRESSED, &Y_tmp, NULL);
    *R1len = EC_POINT_point2buf(ec_group, R1_point, POINT_CONVERSION_UNCOMPRESSED, &R_tmp, NULL);
    if (R1len == 0 || Y1len == 0)                                                                   { return; }

    memcpy(Y1, Y_tmp, *Y1len);
    memcpy(R1, R_tmp, *R1len);


    BN_free(y1_bn);
    BN_free(r1_bn);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(Y1_point);
    EC_POINT_free(R1_point);

}


/**
 * Function Name: request_PK2
 *
 * Description:
 * Get the public key (EC point) Yj from the enclave
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void request_PK2(uint8_t Y2[256], size_t* Y2len,
                 uint8_t R2[256], size_t* R2len,
                 size_t counter)
{
    uint8_t     *R_tmp, *Y_tmp,
                y2j[32], r2j[32];
    BN_CTX      *bn_ctx;
    BIGNUM      *r2_bn, *y2_bn;
    EC_POINT    *R2_point, *Y2_point;


    Y2_point = EC_POINT_new(ec_group);
    R2_point = EC_POINT_new(ec_group);
    bn_ctx = BN_CTX_new();
    r2_bn  = BN_new();
    y2_bn  = BN_new();

    memcpy(y2j, y2, 32);
    for (int i = 0 ; i < counter ; i++) {
        if (0 != ascon_hash(y2j, y2j, 32))                                                          { return; }
    }

    memcpy(r2j, r2, 32);
    for (int i = 0 ; i < counter ; i++) {
        if (0 != ascon_hash(r2j, r2j, 32))                                                          { return; }
    }

    if (NULL == (y2_bn = BN_bin2bn(y2j, 32, 0)))                                                    { return; }   
    if (NULL == (r2_bn = BN_bin2bn(r2j, 32, 0)))                                                    { return; }

    if (0 == BN_mod(y2_bn, y2_bn, order_bn, bn_ctx))                                                { return; }   /* y2 = y2 mod q */
    if (0 == BN_mod(r2_bn, r2_bn, order_bn, bn_ctx))                                                { return; }   /* r2 = r2 mod q */

    if (0 == EC_POINT_mul(ec_group, Y2_point, y2_bn, NULL, NULL, NULL))                             { return; }
    if (0 == EC_POINT_mul(ec_group, R2_point, r2_bn, NULL, NULL, NULL))                             { return; }

    *Y2len = EC_POINT_point2buf(ec_group, Y2_point, POINT_CONVERSION_UNCOMPRESSED, &Y_tmp, NULL);
    *R2len = EC_POINT_point2buf(ec_group, R2_point, POINT_CONVERSION_UNCOMPRESSED, &R_tmp, NULL);
    if (R2len == 0 || Y2len == 0)                                                                   { return; }

    memcpy(Y2, Y_tmp, *Y2len);
    memcpy(R2, R_tmp, *R2len);


    BN_free(y2_bn);
    BN_free(r2_bn);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(Y2_point);
    EC_POINT_free(R2_point);
}


/**
 * Function Name: request_R3
 *
 * Description:
 * Get the public key (EC point) Yj from the enclave
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void request_PK3(uint8_t Y3[256], size_t* Y3len,
                 uint8_t R3[256], size_t* R3len,
                 size_t counter)
{
    uint8_t     *R_tmp, *Y_tmp,
                y3j[32], r3j[32];
    BN_CTX      *bn_ctx;
    BIGNUM      *r3_bn, *y3_bn;
    EC_POINT    *R3_point, *Y3_point;


    Y3_point = EC_POINT_new(ec_group);
    R3_point = EC_POINT_new(ec_group);
    bn_ctx = BN_CTX_new();
    r3_bn  = BN_new();
    y3_bn  = BN_new();

    memcpy(y3j, y3, 32);
    for (int i = 0 ; i < counter ; i++) {        
        if (0 != ascon_hash(y3j, y3j, 32))                                                          { return; }
    }

    memcpy(r3j, r3, 32);
    for (int i = 0 ; i < counter ; i++) {        
        if (0 != ascon_hash(r3j, r3j, 32))                                                          { return; }
    }

    if (NULL == (y3_bn = BN_bin2bn(y3j, 32, 0)))                                                    { return; }   
    if (NULL == (r3_bn = BN_bin2bn(r3j, 32, 0)))                                                    { return; }

    if (0 == BN_mod(y3_bn, y3_bn, order_bn, bn_ctx))                                                { return; }   /* y3 = y3 mod q */
    if (0 == BN_mod(r3_bn, r3_bn, order_bn, bn_ctx))                                                { return; }   /* r3 = r3 mod q */

    if (0 == EC_POINT_mul(ec_group, Y3_point, y3_bn, NULL, NULL, NULL))                             { return; }
    if (0 == EC_POINT_mul(ec_group, R3_point, r3_bn, NULL, NULL, NULL))                             { return; }

    *Y3len = EC_POINT_point2buf(ec_group, Y3_point, POINT_CONVERSION_UNCOMPRESSED, &Y_tmp, NULL);
    *R3len = EC_POINT_point2buf(ec_group, R3_point, POINT_CONVERSION_UNCOMPRESSED, &R_tmp, NULL);
    if (R3len == 0 || Y3len == 0)                                                                   { return; }

    memcpy(Y3, Y_tmp, *Y3len);
    memcpy(R3, R_tmp, *R3len);


    BN_free(y3_bn);
    BN_free(r3_bn);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(Y3_point);
    EC_POINT_free(R3_point);
}
