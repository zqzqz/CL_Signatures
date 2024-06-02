//
// Created by Alexandros Hasikos on 08/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEA_H
#define CL_SIGNATURES_SCHEMEA_H

#include <core.h>
#include <big_464_60.h>
#include <ecp_BN462.h>
#include <ecp2_BN462.h>

typedef struct {
    BIG_464_60 x;
    BIG_464_60 y;
} schemeA_sk;

typedef struct {
    ECP2_BN462 X;
    ECP2_BN462 Y;
} schemeA_pk;

typedef struct {
    ECP_BN462 a;
    ECP_BN462 b;
    ECP_BN462 c;
}schemeA_sig;

void schemeA_generate_sk(schemeA_sk *sk, csprng *prng);

void schemeA_generate_pk(schemeA_pk *pk, schemeA_sk *sk);

void schemeA_sign(schemeA_sig *sig, BIG_464_60 message, schemeA_sk *sk, csprng *prng);

int schemeA_verify(schemeA_sig *sig, BIG_464_60 message, schemeA_pk *pk);


#endif //CL_SIGNATURES_SCHEMEA_H
