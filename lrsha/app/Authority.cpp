
#include "Authority.h"
#include "Enclave_u.h"
#include "util.h"
#include "App.h"
#include <iostream>

Authority::Authority()
{
}

Authority::~Authority()
{
    BN_free(y_sk);
    BN_free(r);
    BN_free(r1);
    BN_free(r2);
    BN_free(r3);
    EC_KEY_free(y1);
    EC_KEY_free(y2);
    EC_KEY_free(y3);
    EC_POINT_free(Y);
}


/**
 * Function Name: init
 *
 * Description:
 * Initialize Authority keys
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init()
{
    BN_CTX* bn_ctx;


    signer_id = 0;
    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    order    = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    bn_ctx  = BN_CTX_new();
    y_sk    = BN_new();
    r       = BN_new();
    r1      = BN_new();
    r2      = BN_new();
    r3      = BN_new();
    y1      = EC_KEY_new();
    y2      = EC_KEY_new();
    y3      = EC_KEY_new();
    Y       = EC_POINT_new(ec_group);
    if (y1 == NULL || y2 == NULL || y3 == NULL || y_sk  == NULL || order == NULL ||
        r1 == NULL || r2 == NULL || r3 == NULL || r  == NULL || ec_group == NULL)           { return 0; }

    if (0 == BN_rand(r1, 256, 1, 0))                                                        { return 0; }   /* r1 = rand() */
    if (0 == BN_rand(r2, 256, 1, 0))                                                        { return 0; }   /* r2 = rand() */
    if (0 == BN_rand(r3, 256, 1, 0))                                                        { return 0; }   /* r3 = rand() */

    if (0 == BN_mod(r1, r1, order, bn_ctx))                                                 { return 0; }   /* r1 = r1 mod q */
    if (0 == BN_mod(r2, r2, order, bn_ctx))                                                 { return 0; }   /* r2 = r2 mod q */
    if (0 == BN_mod(r3, r3, order, bn_ctx))                                                 { return 0; }   /* r3 = r3 mod q */

    if (0 == EC_KEY_set_group(y1, ec_group))                                                { return 0; }   
    if (0 == EC_KEY_set_group(y2, ec_group))                                                { return 0; }
    if (0 == EC_KEY_set_group(y3, ec_group))                                                { return 0; }
    
    if (0 == EC_KEY_generate_key(y1))                                                       { return 0; }
    if (0 == EC_KEY_generate_key(y2))                                                       { return 0; }
    if (0 == EC_KEY_generate_key(y3))                                                       { return 0; }

    y1_sk = (BIGNUM*) EC_KEY_get0_private_key(y1);
    y2_sk = (BIGNUM*) EC_KEY_get0_private_key(y2);
    y3_sk = (BIGNUM*) EC_KEY_get0_private_key(y3);
    if (y1_sk == NULL || y2_sk == NULL || y3_sk == NULL)                                    { return 0; }
    
    if (0 == BN_mod_add(r, r1, r2, order, bn_ctx))                                          { return 0; }   /* r = r1 + r2 mod q */
    if (0 == BN_mod_add(r, r, r3, order, bn_ctx))                                           { return 0; }   /* r = r  + r3 mod q */
    
    if (0 == BN_mod_add(y_sk, y1_sk, y2_sk, order, bn_ctx))                                 { return 0; }   /* y = y1 + y2 mod q */
    if (0 == BN_mod_add(y_sk, y_sk, y3_sk, order, bn_ctx))                                  { return 0; }   /* y = y + y3  mod q */

    if (0 == EC_POINT_mul(ec_group, Y, y_sk, NULL, NULL, NULL))                             { return 0; }   /* Y = alpha^y mod p */


    return 1;
}


/**
 * Function Name: init_parties
 *
 * Description:
 * Initialize ETA process
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init_parties(sgx_enclave_id_t* verifier_id, Signer** signer)
{
    int ret;
    this->signer_id ++;

    ret = this->init_enclave(verifier_id);
    if (ret == 0)                                                                           { return 0; }

    ret = this->sendDP(*verifier_id);
    if (ret == 0)                                                                           { return 0; }
    
    ret = this->SendComm(*verifier_id);
    if (ret == 0)                                                                           { return 0; }

    this->init_signer(signer);

    return 1;
}


/**
 * Function Name: init_enclave
 *
 * Description:
 * Initialize the enclave
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init_enclave(sgx_enclave_id_t* enclave_id)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, enclave_id, NULL);
    if (ret != SGX_SUCCESS)                                                                 { return 0; }
    

    return 1;
}


/**
 * Function Name: destroy_enclave
 *
 * Description:
 * Destory the SGX enclave
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::destroy_enclave(sgx_enclave_id_t enclave_id)
{
    sgx_status_t ret = SGX_SUCCESS;
    
    ret = sgx_destroy_enclave(enclave_id);
    if (ret != SGX_SUCCESS)                                                                 { return 0; }

    return 1;
}


/**
 * Function Name: sendDP
 *
 * Description:
 * Send the domain parameters of the EC curve
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::sendDP(sgx_enclave_id_t enclave_id)
{
    BIGNUM          *p_nb, *a_nb, *b_nb, *order_bn, *cofactor_bn, *gx_bn, *gy_bn;
    uint8_t         *a, *b, *p, *gx, *gy, *order, *cofactor;
    size_t          alen, blen, plen, gxlen, gylen, orderlen, cofactorlen;
    EC_POINT        *G;
    BN_CTX          *ctx;

    p_nb        = BN_new();
    a_nb        = BN_new();
    b_nb        = BN_new();
    gx_bn       = BN_new();
    gy_bn       = BN_new();
    order_bn    = BN_new();
    cofactor_bn = BN_new();
    ctx         = BN_CTX_new();

    G           = (EC_POINT*) EC_GROUP_get0_generator(this->ec_group);
    order_bn    = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    cofactor_bn = (BIGNUM*) EC_GROUP_get0_cofactor(this->ec_group);
    if (0 == EC_GROUP_get_curve(this->ec_group, p_nb, a_nb, b_nb, ctx))                     { return 0; }    
    if (0 == EC_POINT_get_affine_coordinates(this->ec_group, G, gx_bn, gy_bn, ctx))         { return 0; }
    if (G == NULL || order_bn == NULL || cofactor_bn == NULL)                               { return 0; }

    if (0 == encodeBN(p_nb, &p, &plen))                                                     { return 0; }
    if (0 == encodeBN(a_nb, &a, &alen))                                                     { return 0; }
    if (0 == encodeBN(b_nb, &b, &blen))                                                     { return 0; }
    if (0 == encodeBN(gx_bn, &gx, &gxlen))                                                  { return 0; }
    if (0 == encodeBN(gy_bn, &gy, &gylen))                                                  { return 0; }
    if (0 == encodeBN(order_bn, &order, &orderlen))                                         { return 0; }
    if (0 == encodeBN(cofactor_bn, &cofactor, &cofactorlen))                                { return 0; }

    if (0 != send_dp(enclave_id,
                     p, plen,
                     a, alen,
                     b, blen,
                     gx, gxlen,
                     gy, gylen,
                     order, orderlen,
                     cofactor, cofactorlen))                                                { return 0; }


    return 1;
}


/**
 * Function Name: sendComm
 *
 * Description:
 * Send the partial public keys
 * 
 * @param enclave_id    the enclave identification number
 *
 * @return 1 on success, 0 on failure
 */
int Authority::SendComm(sgx_enclave_id_t enclave_id)
{
    uint8_t *r1_d, *r2_d, *r3_d;
    size_t  r1len, r2len, r3len;

    if (0 == encodeBN(this->r1, &r1_d, &r1len))                                             { return 0; }
    if (0 == encodeBN(this->r2, &r2_d, &r2len))                                             { return 0; }
    if (0 == encodeBN(this->r3, &r3_d, &r3len))                                             { return 0; }

    if (0 != send_comm(enclave_id, r1_d, r1len, r2_d, r2len, r3_d, r3len))                  { return 0; }

    return 1;
}


/**
 * Function Name: init_signer
 *
 * Description:
 * Initialize the signer
 * 
 * @param signer     Signer instance
 *
 * @return 1 on success, 0 on failure
 */
int Authority::init_signer(Signer** signer)
{
    uint8_t     *r1_d, *r2_d, *r3_d, *y;
    size_t      r1len, r2len, r3len, ylen;
    Signer      *signer_tmp;


    if (0 == encodeBN(this->r1, &r1_d, &r1len))                                             { return 0; }
    if (0 == encodeBN(this->r2, &r2_d, &r2len))                                             { return 0; }
    if (0 == encodeBN(this->r3, &r3_d, &r3len))                                             { return 0; }
    if (0 == encodeBN(this->y_sk, &y, &ylen))                                               { return 0; }

    /* set the signer id and signer keys */
    signer_tmp = new Signer(this->signer_id);
    signer_tmp->setSignerKeys(this->ec_group,
                              y, ylen,
                              r1_d, r1len,
                              r2_d, r2len,
                              r3_d, r3len);

    *signer = signer_tmp;

    return 1;
}

