//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMED_H
#define CL_SIGNATURES_SCHEMED_H

#include <core.h>
#include <big_464_60.h>
#include <ecp2_BN462.h>
#include <ecp_BN462.h>

typedef struct {
    BIG_464_60 x;
    BIG_464_60 y;
    BIG_464_60 *z;
    uint32_t l;
} schemeD_sk;

typedef struct {
    ECP2_BN462 X;
    ECP2_BN462 Y;
    ECP2_BN462 *Z;
    ECP2_BN462 *W;
    uint32_t l;
    ECP_BN462 g;
    ECP2_BN462 g_2;
} schemeD_pk;

typedef struct {
    ECP_BN462 a;
    ECP_BN462 *A;
    ECP_BN462 b;
    ECP_BN462 *B;
    ECP_BN462 c;
    uint32_t l;
}schemeD_sig;

void schemeD_init_keypair(schemeD_sk* sk, schemeD_pk *pk, uint32_t number_of_messages);

void schemeD_destroy_keypair(schemeD_sk* sk, schemeD_pk *pk);

void schemeD_init_signature(schemeD_sig *sig, uint32_t number_of_messages);

void schemeD_destroy_signature(schemeD_sig *sig);

void schemeD_generate_sk(schemeD_sk *sk, csprng *prng);

void schemeD_generate_pk(schemeD_pk *pk, schemeD_sk *sk);

void schemeD_sign(schemeD_sig *sig, BIG_464_60 *message, schemeD_sk *sk, csprng *prng);

int schemeD_verify(schemeD_sig *sig, BIG_464_60 *message, schemeD_pk *pk);

#endif //CL_SIGNATURES_SCHEMED_H
