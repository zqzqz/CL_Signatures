//
// Created by Alexandros Hasikos on 21/07/2021.
//

#ifndef CL_SIGNATURES_POK_MESSAGE_H
#define CL_SIGNATURES_POK_MESSAGE_H

#include <big_464_60.h>
#include <ecp2_BN462.h>
#include <core.h>

#include <signatures/schemeD/schemeD.h>

void generate_commitment(ECP2_BN462 *commitment, BIG_464_60 *message, schemeD_pk *public_key);

void commitment_conversion(ECP_BN462 *commitment, schemeD_sk *sk, schemeD_sig *sig, BIG_464_60 *message);

void prover_1(ECP2_BN462 *T, BIG_464_60 *t, schemeD_pk *public_key, csprng *prng);

void prover_2(BIG_464_60 *s, BIG_464_60 c, BIG_464_60 *t, BIG_464_60 *message, uint32_t mlen);

int verifier(ECP2_BN462 *T, ECP2_BN462 *commitment, BIG_464_60 *s, BIG_464_60 c, schemeD_pk *public_key);

#endif //CL_SIGNATURES_POK_MESSAGE_H
