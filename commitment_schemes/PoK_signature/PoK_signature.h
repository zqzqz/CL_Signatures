//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_POK_SIGNATURE_H
#define CL_SIGNATURES_POK_SIGNATURE_H

#include <signatures/schemeD/schemeD.h>

#include <fp12_BN462.h>

typedef struct {
    BIG_464_60 r;
} PoK_randomness;

void PoK_compute_blind_signature(schemeD_sig *blind_sig, schemeD_sig *sig, PoK_randomness *proof, csprng *prng);

void PoK_generate_commitment(FP12_BN462 *commitment, PoK_randomness *proof, BIG_464_60 *message, schemeD_pk *pk,
                             schemeD_sig *blind_sig);

void PoK_prover_1(FP12_BN462 *T, BIG_464_60 t1, BIG_464_60 *t2, schemeD_pk *public_key,
                  schemeD_sig *blind_sig, csprng *prng);

void PoK_prover_2(BIG_464_60 s1, BIG_464_60 *s2, BIG_464_60 c, BIG_464_60 t1, BIG_464_60 *t2, BIG_464_60 *message,
                  PoK_randomness *proof, schemeD_sig *sig);

int PoK_verifier(BIG_464_60 s1, BIG_464_60 *s2, BIG_464_60 c, FP12_BN462 *T, FP12_BN462 *commitment,
                 schemeD_pk *public_key, schemeD_sig *blind_sig);

int PoK_verify_pairings(schemeD_sig *blind_sig, schemeD_pk *pk);

#endif //CL_SIGNATURES_POK_SIGNATURE_H
