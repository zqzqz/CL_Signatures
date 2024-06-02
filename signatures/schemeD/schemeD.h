//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMED_H
#define CL_SIGNATURES_SCHEMED_H

#include <core.h>
#include <big_384_58.h>
#include <ecp2_BLS12381.h>
#include <ecp_BLS12381.h>

typedef struct {
    BIG_384_58 x;
    BIG_384_58 y;
    BIG_384_58 *z;
    uint32_t l;
} schemeD_sk;

typedef struct {
    ECP2_BLS12381 X;
    ECP2_BLS12381 Y;
    ECP2_BLS12381 *Z;
    ECP2_BLS12381 *W;
    uint32_t l;
    ECP_BLS12381 g;
    ECP2_BLS12381 g_2;
} schemeD_pk;

typedef struct {
    ECP_BLS12381 a;
    ECP_BLS12381 *A;
    ECP_BLS12381 b;
    ECP_BLS12381 *B;
    ECP_BLS12381 c;
    uint32_t l;
}schemeD_sig;

void schemeD_init_keypair(schemeD_sk* sk, schemeD_pk *pk, uint32_t number_of_messages);

void schemeD_destroy_keypair(schemeD_sk* sk, schemeD_pk *pk);

void schemeD_init_signature(schemeD_sig *sig, uint32_t number_of_messages);

void schemeD_destroy_signature(schemeD_sig *sig);

void schemeD_generate_sk(schemeD_sk *sk, csprng *prng);

void schemeD_generate_pk(schemeD_pk *pk, schemeD_sk *sk);

void schemeD_sign(schemeD_sig *sig, BIG_384_58 *message, schemeD_sk *sk, csprng *prng);

int schemeD_verify(schemeD_sig *sig, BIG_384_58 *message, schemeD_pk *pk);

#endif //CL_SIGNATURES_SCHEMED_H
