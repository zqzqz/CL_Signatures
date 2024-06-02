//
// Created by Alexandros Hasikos on 09/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEB_H
#define CL_SIGNATURES_SCHEMEB_H

#include <core.h>
#include <big_384_58.h>
#include <ecp2_BLS12381.h>
#include <ecp_BLS12381.h>

typedef struct {
    BIG_384_58 x;
    BIG_384_58 y;
    BIG_384_58 z;
} schemeB_sk;

typedef struct {
    ECP2_BLS12381 X;
    ECP2_BLS12381 Y;
    ECP2_BLS12381 Z;
} schemeB_pk;

typedef struct {
    ECP_BLS12381 a;
    ECP_BLS12381 A;
    ECP_BLS12381 b;
    ECP_BLS12381 B;
    ECP_BLS12381 c;
}schemeB_sig;

void schemeB_generate_sk(schemeB_sk *sk, csprng *prng);

void schemeB_generate_pk(schemeB_pk *pk, schemeB_sk *sk);

void schemeB_sign(schemeB_sig *sig, BIG_384_58 message, BIG_384_58 randomness, schemeB_sk *sk, csprng *prng);

int schemeB_verify(schemeB_sig *sig, BIG_384_58 message, BIG_384_58 randomness, schemeB_pk *pk);

#endif //CL_SIGNATURES_SCHEMEB_H
