#include "util.h"
#include "conf.h"
#include "App.h"
#include "Enclave_u.h"
#include <ctime>


int ver_sig(size_t enclave_id,
            uint8_t* msg, size_t msglen,
            sig signature, 
            EC_GROUP* ec_group, EC_POINT* Y,
            int* result, double *req_r1, double *req_r2, double *req_r3, double *agg_R, double *ver_comp)
{
    size_t        R1len, R2len, R3len, ex_hash_len;
    uint8_t       ex_hash[1000], e_ptr[HASH_SIZE], R1_ptr[256], R2_ptr[256], R3_ptr[256];
    BN_CTX        *bn_ctx;
    BIGNUM        *e, *s;
    EC_POINT      *R1, *R2, *R3, *Rsig, *R;
    clock_t       t0, t1;

    
    t0 = clock();
    if (0 != request_R1(enclave_id,
                        R1_ptr, &R1len,
                        signature.counter))                                                     { return 0; }
    t1 = clock();
    *req_r1 = t1 - t0;

    t0 = clock();
    if (0 != request_R2(enclave_id,
                        R2_ptr, &R2len,
                        signature.counter))                                                     { return 0; }
    t1 = clock();
    *req_r2 = t1 - t0;

    t0 = clock();
    if (0 != request_R3(enclave_id,
                        R3_ptr, &R3len,
                        signature.counter))                                                     { return 0; }
    t1 = clock();
    *req_r3 = t1 - t0;


    t0= clock();

    bn_ctx = BN_CTX_new();
    e      = BN_new();
    s      = BN_new();
    R      = EC_POINT_new(ec_group);
    R1     = EC_POINT_new(ec_group);
    R2     = EC_POINT_new(ec_group);
    R3     = EC_POINT_new(ec_group);
    Rsig   = EC_POINT_new(ec_group);
    *result = -1;

    if (0 == EC_POINT_oct2point(ec_group, R1, R1_ptr, R1len, NULL))                             { return 0; }   /* bin2point(R1) */
    if (0 == EC_POINT_oct2point(ec_group, R2, R2_ptr, R2len, NULL))                             { return 0; }   /* bin2point(R2) */
    if (0 == EC_POINT_oct2point(ec_group, R3, R3_ptr, R3len, NULL))                             { return 0; }   /* bin2point(R3) */

    if (0 == EC_POINT_add(ec_group, R, R1, R2, NULL))                                           { return 0; }   /* R = R1 + R2 mod p */
    if (0 == EC_POINT_add(ec_group, R, R, R3, NULL))                                            { return 0; }   /* R = R  + R3 mod p */
    t1 = clock();
    *agg_R = t1 - t0;


    t0 = clock();
    if (0 == concat_str_str(msg, msglen, 
                            signature.x, 32, 
                            ex_hash, &ex_hash_len))                                             { return 0; }
    if (0 != ascon_hash(e_ptr, ex_hash, ex_hash_len))                                           { return 0; }
    e = BN_bin2bn(e_ptr, HASH_SIZE, 0);
    s = BN_bin2bn(signature.s, 32, 0);

    if (0 == EC_POINT_mul(ec_group, Rsig, s, Y, e, bn_ctx))                                     { return 0; }   /* R' = s . G + e . Y */

    *result = EC_POINT_cmp(ec_group, R, Rsig, bn_ctx);                                                          /* res = cmp(R, R) */
    t1 = clock();
    *ver_comp = t1 - t0;

    BN_free(e);
    BN_free(s);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(R);
    EC_POINT_free(R1);
    EC_POINT_free(R2);
    EC_POINT_free(R3);
    EC_POINT_free(Rsig);


    return 1;
}
