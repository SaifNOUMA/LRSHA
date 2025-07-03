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


#include "App.h"
#include "conf.h"
#include "Authority.h"
#include "verify.cpp"
#include "Enclave_u.h"
// #define J 100
// #define INFO
#define DEBUG

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


/* OCall functions */
void ocall_uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}


/* Application entry */
int main(int argc, char *argv[])
{
    Authority*      authority;
    Signer*         signer = NULL;
    uint8_t         *msg, *sig, *xj;
    size_t          count, siglen, msglen, xjlen, J;
    clock_t         t0, t1;
    struct sig      signature;
    int             res, status;
    double          ver_comp_temp, agg_R_temp, sgn_comp_temp, req_r1temp, req_r2temp, req_r3temp, req_r1 = 0.0, req_r2 = 0.0, req_r3 = 0.0, sgn_comp = 0.0, sig_gen = 0.0, sig_ver = 0.0, agg_R = 0.0, ver_comp = 0.0;
    double          sk_upd_temp, sk_comp_temp, r_comp_temp, r_comp=0, x_comp_temp, x_comp=0, sk_upd=0, sk_comp=0;

    // Initialization
    msglen    = atoi(argv[1]);
    J         = atoi(argv[2]);
    msg       = new uint8_t[msglen];
    authority = new Authority();
    status    = authority->init();
    if (status != 1) {
#ifdef INFO
        printf("INFO: Authority initialization failed.\n");
#endif
        return 1;
    }
    authority->init_parties(&global_eid, &signer);

    // Generate the messages to be signed
    for (int i = 0 ; i < J ; i++) {
        if (0 == RAND_bytes(msg, msglen)) {
#ifdef INFO
            printf("INFO: message generation is failed\n");
#endif
            return 1;
        }
    }
    
    for (int i = 0 ; i < J ; i++) {
        // signature generation
        t0 = clock();
        status = signer->sign_message(msg, msglen, &signature,
                                      &r_comp_temp, &x_comp_temp, &sk_comp_temp, &sk_upd_temp, &sgn_comp_temp);
        t1 = clock();
        
        x_comp  += x_comp_temp;
        r_comp  += r_comp_temp;
        sk_comp += sk_comp_temp;
        sk_upd  += sk_upd_temp;
        sgn_comp+= sgn_comp_temp;

        sig_gen += t1 - t0;
        if (status == 1) {
#ifdef INFO
            printf("INFO [j=%d]: signature generation passed successfully\n", i);
#endif
        } else {
#ifdef INFO
            printf("INFO [j=%d]: signature generation failed\n", i);
#endif
            return 1;
        }

        // signature verification
        t0 = clock();
        ver_sig(global_eid, msg, msglen, signature,
                signer->ec_group, &res,
                &req_r1temp, &req_r2temp, &req_r3temp, &agg_R_temp, &ver_comp_temp);
        t1 = clock();
        sig_ver += t1 - t0;
        req_r1 += req_r1temp;
        req_r2 += req_r2temp;
        req_r3 += req_r3temp;
        agg_R  += agg_R_temp;
        ver_comp += ver_comp_temp;

        if (res == 0) {
#ifdef INFO
            printf("INFO [j=%d]: Signature is valid\n", i);
#endif
        } else {
#ifdef INFO
            printf("INFO [j=%d]: Signature is denied\n", i);
#endif
            return 1;
        }
    }

#ifdef DEBUG
    printf("DEBUG: average [sgn-gen] sk-comp: %.2f us\n", sk_comp / J);
    printf("DEBUG: average [sgn-gen] sk-upd:  %.2f us\n", sk_upd / J);
    printf("DEBUG: average [sgn-gen] sgn-comp:%.2f us\n", sgn_comp / J);
    printf("DEBUG: average [sgn-gen] total:   %.2f us\n", sig_gen / J);
    printf("DEBUG: average req-r1:  %.2f us\n", req_r1 / J);
    printf("DEBUG: average req-r2:  %.2f us\n", req_r2 / J);
    printf("DEBUG: average req-r3:  %.2f us\n", req_r3 / J);
    printf("DEBUG: average agg-R:   %.2f us\n", agg_R / J);
    printf("DEBUG: average ver-cop: %.2f us\n", ver_comp / J);
    printf("DEBUG: average sig-ver: %.2f us\n", sig_ver / J);
#endif


    authority->free();
    free(authority);
    free(msg);

    return 0;
}
