//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_POK_SIGNATURE_H
#define CL_SIGNATURES_POK_SIGNATURE_H

#include <signatures/schemeD/schemeD.h>

#include <fp12_BLS12381.h>

typedef struct {
    BIG_384_58 r;
} PoK_randomness;

void PoK_compute_blind_signature(schemeD_sig *blind_sig, schemeD_sig *sig, PoK_randomness *proof, csprng *prng);

void PoK_generate_commitment(FP12_BLS12381 *commitment, PoK_randomness *proof, BIG_384_58 *message, schemeD_pk *pk,
                             schemeD_sig *blind_sig);

void PoK_prover_1(FP12_BLS12381 *T, BIG_384_58 t1, BIG_384_58 *t2, schemeD_pk *public_key,
                  schemeD_sig *blind_sig, csprng *prng);

void PoK_prover_2(BIG_384_58 s1, BIG_384_58 *s2, BIG_384_58 c, BIG_384_58 t1, BIG_384_58 *t2, BIG_384_58 *message,
                  PoK_randomness *proof, schemeD_sig *sig);

int PoK_verifier(BIG_384_58 s1, BIG_384_58 *s2, BIG_384_58 c, FP12_BLS12381 *T, FP12_BLS12381 *commitment,
                 schemeD_pk *public_key, schemeD_sig *blind_sig);

int PoK_verify_pairings(schemeD_sig *blind_sig, schemeD_pk *pk);

#endif //CL_SIGNATURES_POK_SIGNATURE_H
