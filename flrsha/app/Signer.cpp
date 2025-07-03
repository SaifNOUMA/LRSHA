
#include "Signer.h"


Signer::Signer(int id)
{
    this->ID        = id;
    this->y         = BN_new();
    this->counter   = 1;
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
                          uint8_t *y1_arg, size_t y1len_arg,
                          uint8_t *y2_arg, size_t y2len_arg,
                          uint8_t *y3_arg, size_t y3len_arg,
                          uint8_t *r1_arg, size_t r1len_arg,
                          uint8_t *r2_arg, size_t r2len_arg,
                          uint8_t *r3_arg, size_t r3len_arg)
{
    BIGNUM  *order;
    uint8_t *y_ptr;
    size_t  ylen;


    r = BN_new();
    order = (BIGNUM*) EC_GROUP_get0_order(ec_group);
    if (order == NULL || r == NULL)                                                             { return 0; }
    if (1 != RAND_bytes(x, 32))                                                                 { return 0; }

    memcpy(this->y1, y1_arg, y1len_arg);
    memcpy(this->y2, y2_arg, y2len_arg);
    memcpy(this->y3, y3_arg, y3len_arg);

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
                         double *r_comp, double *x_comp, double *sk_comp, double *sk_upd, double *sgn_comp)
{   
    uint8_t         xj_ptr[32], ex_hash[msglen+32], e_ptr[32], *s;
    size_t          xlen, ex_hash_len, siglen;
    BIGNUM          *order, *x_bn, *e_bn, *s_bn;
    BN_CTX          *ctx;

    clock_t t0, t1;


    ctx     = BN_CTX_new();
    x_bn    = BN_new();
    s_bn    = BN_new();
    order   = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    
    // t0 = clock();
    this->compute_sk();
    this->compute_r();
    t1 = clock();
    // *sk_comp = t1-t0;

    // t0 = clock();
    if (0 == concat_str_str(msg, msglen,
                            this->x, 32,
                            ex_hash, &ex_hash_len))                                             { return 0; }
    if (0 != ascon_hash(e_ptr, ex_hash, ex_hash_len))                                           { return 0; }
    if (NULL == (e_bn = BN_bin2bn(e_ptr, HASH_SIZE, 0)))                                        { return 0; }

    if (0 == BN_mul(x_bn, e_bn, this->y, ctx))                                                  { return 0; }   /* s' = e . y */
    if (0 == BN_mod_sub(s_bn, this->r, x_bn, order, ctx))                                       { return 0; }   /* s = r - e * y */

    if (0 == encodeBN(s_bn, &s, &siglen))                                                       { return 0; }
    
    /* copy results to the signature structure */
    memcpy(signature->s, s, HASH_SIZE);
    memcpy(signature->x, this->x, HASH_SIZE);
    signature->counter = this->counter;
    // t1 = clock();
    // *sgn_comp = t1-t0;

    // t0 = clock();
    this->update_keys();
    this->counter ++;
    // t1 = clock();
    // *sk_upd = t1-t0;


    // BN_free(x_bn);
    // BN_free(s_bn);
    // BN_CTX_free(ctx);

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


/**
 * Function Name: update_keys
 *
 * Description:
 * Update the signer keys when signing occurs
 * @param sig: the signature
 * @param siglen: length of the signature
 *
 * @return 1 on success, 0 on failure
 */
int Signer::update_keys()
{
    if (0 != ascon_hash(this->y1, this->y1, 32))           { return 0; }
    if (0 != ascon_hash(this->y2, this->y2, 32))           { return 0; }
    if (0 != ascon_hash(this->y3, this->y3, 32))           { return 0; }

    if (0 != ascon_hash(this->r1, this->r1, 32))           { return 0; }
    if (0 != ascon_hash(this->r2, this->r2, 32))           { return 0; }
    if (0 != ascon_hash(this->r3, this->r3, 32))           { return 0; }

    if (0 != ascon_hash(this->x, this->x, 32))             { return 0; }

    return 1;
}


/**
 * Function Name: compute_sk
 *
 * Description:
 * Update the signer keys when signing occurs
 *
 * @return 1 on success, 0 on failure
 */
int Signer::compute_sk()
{
    BIGNUM *y1b, *y2b, *y3b, *order;
    BN_CTX *ctx;

    order = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    ctx   = BN_CTX_new();


    if (NULL == (y1b = BN_bin2bn(this->y1, 32, 0)))                                             { return 0; }
    if (NULL == (y2b = BN_bin2bn(this->y2, 32, 0)))                                             { return 0; }
    if (NULL == (y3b = BN_bin2bn(this->y3, 32, 0)))                                             { return 0; }

    if (0 == BN_mod_add(this->y, y1b, y2b, order, ctx))                                         { return 0; }   /* y = y1 + y2 mod q */
    if (0 == BN_mod_add(this->y, this->y, y3b, order, ctx))                                     { return 0; }   /* y = y  + y3 mod q */


    BN_CTX_free(ctx);

    return 1;
}


/**
 * Function Name: compute_r
 *
 * Description:
 * Update the signer keys when signing occurs
 *
 * @return 1 on success, 0 on failure
 */
int Signer::compute_r()
{
    uint8_t r1j[32], r2j[32], r3j[32];
    BIGNUM  *r1_bn, *r2_bn, *r3_bn, *order;
    BN_CTX  *ctx;

    order = (BIGNUM*) EC_GROUP_get0_order(this->ec_group);
    ctx   = BN_CTX_new();

    if (NULL == (r1_bn = BN_bin2bn(this->r1, 32, 0)))                                                { return 0; }
    if (NULL == (r2_bn = BN_bin2bn(this->r2, 32, 0)))                                                { return 0; }
    if (NULL == (r3_bn = BN_bin2bn(this->r3, 32, 0)))                                                { return 0; }

    if (0 == BN_mod_add(r, r1_bn, r2_bn, order, ctx))                                           { return 0; }   /* r = r1 + r2 mod q */
    if (0 == BN_mod_add(r, r, r3_bn, order, ctx))                                               { return 0; }   /* r = r  + r3 mod q */


    BN_CTX_free(ctx);

    return 1;
}
