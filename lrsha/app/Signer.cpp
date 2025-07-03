
#include "Signer.h"


Signer::Signer(int id)
{
    this->ID        = id;
    this->y         = BN_new();
    this->counter   = 0;
}

Signer::~Signer()
{
}


/**
 * Function Name: setSignerKeys
 *
 * Description:
 * Set the signer's private/public keys
 * @param ec_group: EC group that hold EC domain parameters
 * @param ec_key: The private/public EC keys for the signer.
 *
 * @return 1 on success, 0 on failure
 */
int Signer::setSignerKeys(EC_GROUP *ec_group,
                          uint8_t *y_arg, size_t ylen_arg,
                          uint8_t *r1_arg, size_t r1len_arg,
                          uint8_t *r2_arg, size_t r2len_arg,
                          uint8_t *r3_arg, size_t r3len_arg)
{
    BIGNUM  *order;
    uint8_t *y_ptr;
    size_t  ylen;


    this->y = BN_bin2bn(y_arg, ylen_arg, NULL);
    order = (BIGNUM*) EC_GROUP_get0_order(ec_group);
    if (this->y == NULL || order == NULL)                                                       { return 0; }
    if (1 != RAND_bytes(x, 32))                                                                 { return 0; }

    memcpy(r1, r1_arg, r1len_arg);
    memcpy(r2, r2_arg, r2len_arg);
    memcpy(r3, r3_arg, r3len_arg);

    this->ec_group  = ec_group;
    this->counter   = 0;

    return 1;
}


/**
 * Function Name: sign_message
 *
 * Description:
 * Sign the given message using ETA scheme
 * @param message: message to sign
 * @param messagelen: length of the message
 *
 * @return 1 on success, 0 on failure
 */
int Signer::sign_message(uint8_t* msg, size_t msglen,
                         struct sig *signature, 
                         double *sk_comp, double *sgn_comp)
{   
    uint8_t         xj_ptr[32], ex_hash[msglen+32], e_ptr[32], *s,
                    r1j[32], r2j[32], r3j[32];
    size_t          xlen, rlen, ex_hash_len, siglen;
    BIGNUM          *order, *x_bn, *e_bn, *s_bn, *r_bn, *r1_bn, *r2_bn, *r3_bn;
    BN_CTX          *ctx;

    clock_t t0, t1;


    t0 = clock();
    ctx     = BN_CTX_new();
    x_bn    = BN_new();
    r_bn    = BN_new();
    s_bn    = BN_new();
    order   = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    
    if (0 != ascon_hash(r1j, r1, 32))                                                           { return 0; }
    if (0 != ascon_hash(r2j, r2, 32))                                                           { return 0; }
    if (0 != ascon_hash(r3j, r3, 32))                                                           { return 0; }

    if (NULL == (r1_bn = BN_bin2bn(r1j, 32, 0)))                                                { return 0; }
    if (NULL == (r2_bn = BN_bin2bn(r2j, 32, 0)))                                                { return 0; }
    if (NULL == (r3_bn = BN_bin2bn(r3j, 32, 0)))                                                { return 0; }

    if (0 == BN_mod_add(r_bn, r1_bn, r2_bn, order, ctx))                                        { return 0; }   /* r = r1 + r2 mod q */
    if (0 == BN_mod_add(r_bn, r_bn, r3_bn, order, ctx))                                         { return 0; }   /* r = r  + r3 mod q */

    if (0 != ascon_hash(xj_ptr, this->x, 32))                                                   { return 0; }
    t1 = clock();
    *sk_comp = t1-t0;

    t0 = clock();
    if (0 == concat_str_str(msg, msglen,
                            xj_ptr, sizeof(xj_ptr),
                            ex_hash, &ex_hash_len))                                             { return 0; }
    if (0 != ascon_hash(e_ptr, ex_hash, ex_hash_len))                                           { return 0; }
    if (NULL == (e_bn = BN_bin2bn(e_ptr, HASH_SIZE, 0)))                                        { return 0; }

    if (0 == BN_mul(x_bn, e_bn, this->y, ctx))                                                  { return 0; }   /* s' = e . y */
    if (0 == BN_mod_sub(s_bn, r_bn, x_bn, order, ctx))                                          { return 0; }   /* s = r - e * y */

    if (0 == encodeBN(s_bn, &s, &siglen))                                                       { return 0; }
    
    /* copy results to the signature structure */
    memcpy(signature->s, s, HASH_SIZE);
    memcpy(signature->x, xj_ptr, HASH_SIZE);
    signature->counter = this->counter;

    this->counter ++;


    BN_free(x_bn);
    BN_free(r_bn);
    BN_free(s_bn);
    BN_CTX_free(ctx);

    t1 = clock();
    *sgn_comp = t1-t0;

    return 1;
}


/**
 * Function Name: send_signature
 *
 * Description:
 * Send the signature to the verifier (SGX enclave)
 * @param sig: the signature
 * @param siglen: length of the signature
 *
 * @return 1 on success, 0 on failure
 */
int Signer::send_signature(unsigned char* sig, size_t siglen)
{

    return 1;
}
