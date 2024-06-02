//
// Created by Alexandros Hasikos on 21/07/2021.
//

#ifndef CL_SIGNATURES_POK_MESSAGE_H
#define CL_SIGNATURES_POK_MESSAGE_H

#include <big_384_58.h>
#include <ecp2_BLS12381.h>
#include <core.h>

#include <signatures/schemeD/schemeD.h>

void generate_commitment(ECP2_BLS12381 *commitment, BIG_384_58 *message, schemeD_pk *public_key);

void commitment_conversion(ECP_BLS12381 *commitment, schemeD_sk *sk, schemeD_sig *sig, BIG_384_58 *message);

void prover_1(ECP2_BLS12381 *T, BIG_384_58 *t, schemeD_pk *public_key, csprng *prng);

void prover_2(BIG_384_58 *s, BIG_384_58 c, BIG_384_58 *t, BIG_384_58 *message, uint32_t mlen);

int verifier(ECP2_BLS12381 *T, ECP2_BLS12381 *commitment, BIG_384_58 *s, BIG_384_58 c, schemeD_pk *public_key);

#endif //CL_SIGNATURES_POK_MESSAGE_H
