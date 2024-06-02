//
// Created by Alexandros Hasikos on 08/07/2021.
//

#include "schemeA.h"
#include <utils/utils.h>

#include <string.h>
#include <pair_BN462.h>
#include <params.h>

void schemeA_generate_sk(schemeA_sk *sk, csprng *prng) {
    BIG_464_60_random(sk->x, prng);
    BIG_464_60_random(sk->y, prng);
}

void schemeA_generate_pk(schemeA_pk *pk, schemeA_sk *sk) {
    ECP2_BN462_generator(&pk->Y);
    ECP2_BN462_generator(&pk->X);

    PAIR_BN462_G2mul(&pk->X, sk->x);
    PAIR_BN462_G2mul(&pk->Y, sk->y);
}

void schemeA_sign(schemeA_sig *sig, BIG_464_60 message, schemeA_sk *sk, csprng *prng) {
    //Generate random element
    FP_BN462 rnd;
    FP_BN462_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN462_map2point(&sig->a, &rnd);

    // Compute a^y
    ECP_BN462_copy(&sig->b, &sig->a);
    PAIR_BN462_G1mul(&sig->b, sk->y);

    //Compute a^(x + xym)
    BIG_464_60 x_plus_xym, xym;

    BIG_464_60_mul_xyz(&xym, sk->x, sk->y, message);
    BIG_464_60_modadd(x_plus_xym, xym, sk->x, MODULUS);

    ECP_BN462_copy(&sig->c, &sig->a);
    PAIR_BN462_G1mul(&sig->c, x_plus_xym);
}

int schemeA_verify(schemeA_sig *sig, BIG_464_60 message, schemeA_pk *pk) {
    int res = 0;

    ECP2_BN462 G2;
    ECP2_BN462_generator(&G2);

    //Verification 1
    res += pairing_and_equality_check(&pk->Y, &sig->a, &G2, &sig->b);

    //Verification 2
    FP12_BN462 lhs, rhs;
    ECP_BN462 b_times_m;

    ECP_BN462_copy(&b_times_m, &sig->b);
    PAIR_BN462_G1mul(&b_times_m, message);

    two_element_pairing_and_multiplication(&lhs, &pk->X, &sig->a, &pk->X, &b_times_m);

    PAIR_BN462_ate(&rhs, &G2, &sig->c);
    PAIR_BN462_fexp(&rhs);

    res += FP12_BN462_equals(&lhs, &rhs);

    if( res == 2 ) return 1;

    return 0;
}
