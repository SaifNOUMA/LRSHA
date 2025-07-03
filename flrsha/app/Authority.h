#ifndef AUTH_H
#define AUTH_H

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "conf.h"
#include "Signer.h"

class Authority
{
private:

    int             signer_id;
    unsigned char   *msk;
    EC_KEY          *y1, *y2, *y3;
    BIGNUM          *r1, *r2, *r3, *y1_sk, *y2_sk, *y3_sk, *order;
    EC_GROUP*       ec_group;

public:
    Authority();
    ~Authority();

    /* Initialization */
    int init();
    int init_parties(sgx_enclave_id_t* verifier_id, Signer** signer);
    
    int init_signer(Signer** signer);
    
    int init_enclave(sgx_enclave_id_t* enclave_id);
    int SendComm(sgx_enclave_id_t enclave_id);
    int sendDP(sgx_enclave_id_t enclave_id);
    int destroy_enclave(sgx_enclave_id_t enclave_id);
    int free();


    EC_POINT        *Y, *Y1, *Y2, *Y3;
    EC_POINT        *R1, *R2, *R3;
};


#endif
