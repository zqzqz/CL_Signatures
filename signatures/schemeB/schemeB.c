//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include "schemeB.h"
#include <utils/utils.h>
#include <pair_BLS12381.h>

void schemeB_generate_sk(schemeB_sk *sk, csprng *prng) {
    BIG_384_58_random(sk->x, prng);
    BIG_384_58_random(sk->y, prng);
    BIG_384_58_random(sk->z, prng);
}

void schemeB_generate_pk(schemeB_pk *pk, schemeB_sk *sk) {
    ECP2_BLS12381_generator(&pk->Y);
    ECP2_BLS12381_generator(&pk->X);
    ECP2_BLS12381_generator(&pk->Z);

    PAIR_BLS12381_G2mul(&pk->X, sk->x);
    PAIR_BLS12381_G2mul(&pk->Y, sk->y);
    PAIR_BLS12381_G2mul(&pk->Z, sk->z);
}

void schemeB_sign(schemeB_sig *sig, BIG_384_58 message, BIG_384_58 randomness, schemeB_sk *sk, csprng *prng) {
    //Generate random element
    FP_BLS12381 rnd;
    FP_BLS12381_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BLS12381_map2point(&sig->a, &rnd);

    //Compute A -> a^z
    ECP_BLS12381_copy(&sig->A, &sig->a);
    PAIR_BLS12381_G1mul(&sig->A, sk->z);

    // Compute b -> a^y
    ECP_BLS12381_copy(&sig->b, &sig->a);
    PAIR_BLS12381_G1mul(&sig->b, sk->y);

    //Compute B -> A^y
    ECP_BLS12381_copy(&sig->B, &sig->A);
    PAIR_BLS12381_G1mul(&sig->B, sk->y);

    //Compute c-> a^(x + mxy) * A^(xyr)
    BIG_384_58 x_plus_xym, xym, xyr;
    ECP_BLS12381 a_times_x_plus_xym, A_times_xyr;

    BIG_384_58_mul_xyz(&xym, sk->x, sk->y, message);
    BIG_384_58_modadd(x_plus_xym, xym, sk->x, (int64_t *)CURVE_Order_BLS12381);

    ECP_BLS12381_copy(&a_times_x_plus_xym, &sig->a);
    PAIR_BLS12381_G1mul(&a_times_x_plus_xym, x_plus_xym);

    BIG_384_58_mul_xyz(&xyr, sk->x, sk->y, randomness);

    ECP_BLS12381_copy(&A_times_xyr, &sig->A);
    PAIR_BLS12381_G1mul(&A_times_xyr, xyr);

    // Multiply the two
    ECP_BLS12381_copy(&sig->c, &a_times_x_plus_xym);
    ECP_BLS12381_add(&sig->c, &A_times_xyr);
}

int schemeB_verify(schemeB_sig *sig, BIG_384_58 message, BIG_384_58 randomness, schemeB_pk *pk) {
    int res = 0;
    //Verification 1

    ECP2_BLS12381 G2;
    ECP2_BLS12381_generator(&G2);

    res += pairing_and_equality_check(&pk->Z, &sig->a, &G2, &sig->A);

    //Verification 2
    res += pairing_and_equality_check(&pk->Y, &sig->a, &G2, &sig->b);

    //Verification 3
    res += pairing_and_equality_check(&pk->Y, &sig->A, &G2, &sig->B);

    //Verification 4
    FP12_BLS12381 rhs, lhs;
    ECP_BLS12381 b_times_m, B_times_r;

    ECP_BLS12381_copy(&b_times_m, &sig->b);
    PAIR_BLS12381_G1mul(&b_times_m, message);

    ECP_BLS12381_copy(&B_times_r, &sig->B);
    PAIR_BLS12381_G1mul(&B_times_r, randomness);

    three_element_pairing_and_multiplication(&lhs, &pk->X, &sig->a, &pk->X, &b_times_m, &pk->X, &B_times_r);

    PAIR_BLS12381_ate(&rhs, &G2, &sig->c);
    PAIR_BLS12381_fexp(&rhs);

    res += FP12_BLS12381_equals(&lhs, &rhs);

    if( res == 4 ) return 1;

    return 0;
}