//
// Created by Alexandros Hasikos on 08/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEA_H
#define CL_SIGNATURES_SCHEMEA_H

#include <core.h>
#include <big_384_58.h>
#include <ecp_BLS12381.h>
#include <ecp2_BLS12381.h>

typedef struct {
    BIG_384_58 x;
    BIG_384_58 y;
} schemeA_sk;

typedef struct {
    ECP2_BLS12381 X;
    ECP2_BLS12381 Y;
} schemeA_pk;

typedef struct {
    ECP_BLS12381 a;
    ECP_BLS12381 b;
    ECP_BLS12381 c;
}schemeA_sig;

void schemeA_generate_sk(schemeA_sk *sk, csprng *prng);

void schemeA_generate_pk(schemeA_pk *pk, schemeA_sk *sk);

void schemeA_sign(schemeA_sig *sig, BIG_384_58 message, schemeA_sk *sk, csprng *prng);

int schemeA_verify(schemeA_sig *sig, BIG_384_58 message, schemeA_pk *pk);


#endif //CL_SIGNATURES_SCHEMEA_H
