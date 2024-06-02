//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "PoK_signature.h"
#include "params.h"

#include <pair_BLS12381.h>
#include <utils/utils.h>

void PoK_compute_blind_signature(schemeD_sig *blind_sig, schemeD_sig *sig, PoK_randomness *proof, csprng *prng) {
    BIG_384_58 r_prime;
    BIG_384_58_random(r_prime, prng);

    ECP_BLS12381_copy(&blind_sig->a, &sig->a);
    PAIR_BLS12381_G1mul(&blind_sig->a, proof->r);

    ECP_BLS12381_copy(&blind_sig->b, &sig->b);
    PAIR_BLS12381_G1mul(&blind_sig->b, proof->r);

    ECP_BLS12381_copy(&blind_sig->c, &sig->c);
    PAIR_BLS12381_G1mul(&blind_sig->c, proof->r);

    PAIR_BLS12381_G1mul(&blind_sig->c, r_prime);

    for(int i = 0; i < sig->l; i++) {
        ECP_BLS12381_copy(&blind_sig->A[i], &sig->A[i]);
        PAIR_BLS12381_G1mul(&blind_sig->A[i], proof->r);

        ECP_BLS12381_copy(&blind_sig->B[i], &sig->B[i]);
        PAIR_BLS12381_G1mul(&blind_sig->B[i], proof->r);
    }
}

void PoK_generate_commitment(FP12_BLS12381 *commitment, PoK_randomness *proof, BIG_384_58 *message, schemeD_pk *pk,
                             schemeD_sig *blind_sig) {

    FP12_BLS12381 Vx, Vxy, Vxy_i, prod;
    ECP_BLS12381 B_times_m_i, b_blind, a_blind;

    FP12_BLS12381_one(commitment);
    FP12_BLS12381_one(&prod);

    ECP_BLS12381_copy(&a_blind, &blind_sig->a);
    PAIR_BLS12381_G1mul(&a_blind, proof->r);
    PAIR_BLS12381_ate(&Vx, &pk->X, &a_blind);
    PAIR_BLS12381_fexp(&Vx);

    ECP_BLS12381_copy(&b_blind, &blind_sig->b);
    PAIR_BLS12381_G1mul(&b_blind, message[0]);
    PAIR_BLS12381_ate(&Vxy, &pk->X, &b_blind);
    PAIR_BLS12381_fexp(&Vxy);

    for(int i = 1; i < pk->l; i++) {
        ECP_BLS12381_copy(&B_times_m_i, &blind_sig->B[i]);
        PAIR_BLS12381_G1mul(&B_times_m_i, message[i]);

        PAIR_BLS12381_ate(&Vxy_i, &pk->X, &B_times_m_i);
        PAIR_BLS12381_fexp(&Vxy_i);

        FP12_BLS12381_mul(&prod, &Vxy_i);
    }

    FP12_BLS12381_mul(commitment, &Vx);
    FP12_BLS12381_mul(commitment, &Vxy);
    FP12_BLS12381_mul(commitment, &prod);
}

void
PoK_prover_1(FP12_BLS12381 *T, BIG_384_58 t1, BIG_384_58 *t2, schemeD_pk *public_key, schemeD_sig *blind_sig,
             csprng *prng) {

    FP12_BLS12381_one(T);

    //Generate t1 and t2
    BIG_384_58_random(t1, prng);

    for(int i = 0; i < public_key->l; i++) {
        BIG_384_58_random(t2[i], prng);
    }

    FP12_BLS12381 Vx, Vxy, Vxy_i, prod;
    ECP_BLS12381 B_times_m_i, b_blind, a_blind;

    FP12_BLS12381_one(&prod);

    ECP_BLS12381_copy(&a_blind, &blind_sig->a);
    PAIR_BLS12381_G1mul(&a_blind, t1);
    PAIR_BLS12381_ate(&Vx, &public_key->X, &a_blind);
    PAIR_BLS12381_fexp(&Vx);

    ECP_BLS12381_copy(&b_blind, &blind_sig->b);
    PAIR_BLS12381_G1mul(&b_blind, t2[0]);
    PAIR_BLS12381_ate(&Vxy, &public_key->X, &b_blind);
    PAIR_BLS12381_fexp(&Vxy);

    for(int i = 1; i < public_key->l; i++) {
        ECP_BLS12381_copy(&B_times_m_i, &blind_sig->B[i]);
        PAIR_BLS12381_G1mul(&B_times_m_i, t2[i]);

        PAIR_BLS12381_ate(&Vxy_i, &public_key->X, &B_times_m_i);
        PAIR_BLS12381_fexp(&Vxy_i);

        FP12_BLS12381_mul(&prod, &Vxy_i);
    }

    FP12_BLS12381_mul(T, &Vx);
    FP12_BLS12381_mul(T, &Vxy);
    FP12_BLS12381_mul(T, &prod);
}

void PoK_prover_2(BIG_384_58 s1, BIG_384_58 *s2, BIG_384_58 c, BIG_384_58 t1, BIG_384_58 *t2, BIG_384_58 *message,
                  PoK_randomness *proof, schemeD_sig *sig) {

    BIG_384_58 tmp;

    BIG_384_58_modmul(tmp, proof->r, c, MODULUS);
    BIG_384_58_modadd(s1, tmp, t1, MODULUS);

    BIG_384_58_modmul(tmp, message[0], c, MODULUS);
    BIG_384_58_modadd(s2[0], tmp, t2[0], MODULUS);
    
    for(int i = 1; i < sig->l; i++) {
        BIG_384_58_modmul(tmp, message[i], c, MODULUS);
        BIG_384_58_modadd(s2[i], tmp, t2[i], MODULUS);
    }
}


int PoK_verifier(BIG_384_58 s1, BIG_384_58 *s2, BIG_384_58 c, FP12_BLS12381 *T, FP12_BLS12381 *commitment,
                 schemeD_pk *public_key, schemeD_sig *blind_sig) {

    int res = 0;

    FP12_BLS12381 Vx, Vxy, Vxy_i, prod, lhs, rhs;
    ECP_BLS12381 B_times_s_i, b_blind, a_blind;

    FP12_BLS12381_one(&prod);
    FP12_BLS12381_one(&lhs);
    FP12_BLS12381_one(&rhs);

    ECP_BLS12381_copy(&a_blind, &blind_sig->a);
    PAIR_BLS12381_G1mul(&a_blind, s1);
    PAIR_BLS12381_ate(&Vx, &public_key->X, &a_blind);
    PAIR_BLS12381_fexp(&Vx);

    ECP_BLS12381_copy(&b_blind, &blind_sig->b);
    PAIR_BLS12381_G1mul(&b_blind, s2[0]);
    PAIR_BLS12381_ate(&Vxy, &public_key->X, &b_blind);
    PAIR_BLS12381_fexp(&Vxy);

    for(int i = 1; i < public_key->l; i++) {
        ECP_BLS12381_copy(&B_times_s_i, &blind_sig->B[i]);
        PAIR_BLS12381_G1mul(&B_times_s_i, s2[i]);

        PAIR_BLS12381_ate(&Vxy_i, &public_key->X, &B_times_s_i);
        PAIR_BLS12381_fexp(&Vxy_i);

        FP12_BLS12381_mul(&prod, &Vxy_i);
    }

    FP12_BLS12381_mul(&lhs, &Vx);
    FP12_BLS12381_mul(&lhs, &Vxy);
    FP12_BLS12381_mul(&lhs, &prod);

    FP12_BLS12381_pow(&rhs, commitment, c);
    FP12_BLS12381_mul(&rhs, T);

    FP12_BLS12381_equals(&lhs, &rhs) ? res++ : (res = 0);

    return res;
}

int PoK_verify_pairings(schemeD_sig *blind_sig, schemeD_pk *pk) {
    int v = 0, res = 0;

    for(int i = 0; i < pk->l; i++) {
        v += pairing_and_equality_check(&pk->Z[i], &blind_sig->a, &pk->g_2, &blind_sig->A[i]);
        v += pairing_and_equality_check(&pk->Y, &blind_sig->A[i], &pk->g_2, &blind_sig->B[i]);
    }

    if(v == pk->l * 2) res++;

    pairing_and_equality_check(&pk->Y, &blind_sig->a, &pk->g_2, &blind_sig->b) ? res++ : (res = 0);

    return res;
}