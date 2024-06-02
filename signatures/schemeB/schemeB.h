//
// Created by Alexandros Hasikos on 09/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEB_H
#define CL_SIGNATURES_SCHEMEB_H

#include <core.h>
#include <big_464_60.h>
#include <ecp2_BN462.h>
#include <ecp_BN462.h>

typedef struct {
    BIG_464_60 x;
    BIG_464_60 y;
    BIG_464_60 z;
} schemeB_sk;

typedef struct {
    ECP2_BN462 X;
    ECP2_BN462 Y;
    ECP2_BN462 Z;
} schemeB_pk;

typedef struct {
    ECP_BN462 a;
    ECP_BN462 A;
    ECP_BN462 b;
    ECP_BN462 B;
    ECP_BN462 c;
}schemeB_sig;

void schemeB_generate_sk(schemeB_sk *sk, csprng *prng);

void schemeB_generate_pk(schemeB_pk *pk, schemeB_sk *sk);

void schemeB_sign(schemeB_sig *sig, BIG_464_60 message, BIG_464_60 randomness, schemeB_sk *sk, csprng *prng);

int schemeB_verify(schemeB_sig *sig, BIG_464_60 message, BIG_464_60 randomness, schemeB_pk *pk);

#endif //CL_SIGNATURES_SCHEMEB_H
