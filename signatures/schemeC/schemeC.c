//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include "schemeC.h"
#include <utils/utils.h>
#include <pair_BN462.h>
#include <string.h>

void schemeC_init_keypair(schemeC_sk* sk, schemeC_pk *pk, uint32_t number_of_messages) {
    sk->z = malloc(sizeof(BIG_464_60) * number_of_messages);
    sk->l = number_of_messages;

    pk->Z = malloc(sizeof(ECP2_BN462) * number_of_messages);
    pk->l = number_of_messages;
}

void schemeC_destroy_keypair(schemeC_sk* sk, schemeC_pk *pk) {
    memset(sk->x, 0, sizeof(BIG_464_60));
    memset(sk->y, 0, sizeof(BIG_464_60));
    memset(sk->z, 0, (sk->l * sizeof(BIG_464_60)));
    free(sk->z);

    memset(&pk->X, 0, sizeof(ECP2_BN462));
    memset(&pk->Y, 0, sizeof(ECP2_BN462));
    memset(pk->Z, 0, (pk->l * sizeof(ECP2_BN462)));
    free(pk->Z);
}

void schemeC_init_signature(schemeC_sig *sig, uint32_t number_of_messages) {
    sig->A = malloc(sizeof(ECP_BN462) * number_of_messages);
    sig->B = malloc(sizeof(ECP_BN462) * number_of_messages);
    sig->l = number_of_messages;
}

void schemeC_destroy_signature(schemeC_sig *sig) {
    memset(&sig->a, 0, sizeof(ECP_BN462));
    memset(&sig->b, 0, sizeof(ECP_BN462));
    memset(&sig->c, 0, sizeof(ECP_BN462));
    memset(sig->A, 0, (sig->l * sizeof(ECP_BN462)));
    memset(sig->B, 0, (sig->l * sizeof(ECP_BN462)));

    free(sig->A);
    free(sig->B);
}

void schemeC_generate_sk(schemeC_sk *sk, csprng *prng) {
    BIG_464_60_random(sk->x, prng);
    BIG_464_60_random(sk->y, prng);

    for(int i = 0; i < sk->l; i++) {
        BIG_464_60_random(sk->z[i], prng);
    }
}

void schemeC_generate_pk(schemeC_pk *pk, schemeC_sk *sk) {

    ECP2_BN462_generator(&pk->Y);
    ECP2_BN462_generator(&pk->X);

    PAIR_BN462_G2mul(&pk->X, sk->x);
    PAIR_BN462_G2mul(&pk->Y, sk->y);

    for(int i = 0; i < pk->l; i++) {
        ECP2_BN462_generator(&pk->Z[i]);
        PAIR_BN462_G2mul(&pk->Z[i], sk->z[i]);
    }
}

void schemeC_sign(schemeC_sig *sig, BIG_464_60 *message, schemeC_sk *sk, csprng *prng) {
    //Generate random element
    FP_BN462 rnd;
    FP_BN462_rand(&rnd, prng);

    //Map element to point and compute a
    ECP_BN462_map2point(&sig->a, &rnd);

    //Compute A[i] -> a^z[i] and B[i] -> A[i]^y
    for(int i = 0; i < sk->l; i++) {
        ECP_BN462_copy(&sig->A[i], &sig->a);
        PAIR_BN462_G1mul(&sig->A[i], sk->z[i]);

        ECP_BN462_copy(&sig->B[i], &sig->A[i]);
        PAIR_BN462_G1mul(&sig->B[i], sk->y);
    }

    // Compute b -> a^y
    ECP_BN462_copy(&sig->b, &sig->a);
    PAIR_BN462_G1mul(&sig->b, sk->y);

    //Compute c-> a^(x + mxy) * A^(xyr)
    BIG_464_60 x_plus_xym, x_times_y, xym, xyr;
    ECP_BN462 a_times_x_plus_xym;

    BIG_464_60_mul_xyz(&xym, sk->x, sk->y, message[0]);
    BIG_464_60_modadd(x_plus_xym, xym, sk->x, (int64_t *)CURVE_Order_BN462);

    ECP_BN462_copy(&a_times_x_plus_xym, &sig->a);
    PAIR_BN462_G1mul(&a_times_x_plus_xym, x_plus_xym);


    BIG_464_60 xy_times_m_i;
    ECP_BN462 product_A_times_xym_i, sum;
    ECP_BN462_inf(&sum);

    BIG_464_60_modmul(x_times_y, sk->x, sk->y, (int64_t *)CURVE_Order_BN462);

    for(int i = 1; i < sk->l; i++) {
        BIG_464_60_modmul(xy_times_m_i, x_times_y, message[i], (int64_t *)CURVE_Order_BN462);

        ECP_BN462_copy(&product_A_times_xym_i, &sig->A[i]);
        PAIR_BN462_G1mul(&product_A_times_xym_i, xy_times_m_i);

        ECP_BN462_add(&sum, &product_A_times_xym_i);
    }
    // Multiply the two
    ECP_BN462_copy(&sig->c, &a_times_x_plus_xym);
    ECP_BN462_add(&sig->c, &sum);
}

int schemeC_verify(schemeC_sig *sig, BIG_464_60 *message, schemeC_pk *pk) {
    int res = 0, v1 = 0, v2 = 0;

    ECP2_BN462 G2;
    ECP2_BN462_generator(&G2);

    //Verification 1
    for(int i = 0; i < pk->l; i++) {
        v1 += pairing_and_equality_check(&pk->Z[i], &sig->a, &G2, &sig->A[i]);
    }

    if( v1 == pk->l ) res ++;

    //Verification 2
    res += pairing_and_equality_check(&pk->Y, &sig->a, &G2, &sig->b);

    //Verification 3
    for(int i = 0; i < pk->l; i++) {
        v2 += pairing_and_equality_check(&pk->Y, &sig->A[i], &G2, &sig->B[i]);
    }

    if( v2 == pk->l ) res++;

    //Verification 4
    FP12_BN462 inner_element, inner_product, Xa_times_Xb, rhs, lhs;
    ECP_BN462 b_times_m_0, B_i_times_m_i;

    FP12_BN462_one(&inner_product);

    ECP_BN462_copy(&b_times_m_0, &sig->b);
    PAIR_BN462_G1mul(&b_times_m_0, message[0]);

    two_element_pairing_and_multiplication(&Xa_times_Xb, &pk->X, &sig->a, &pk->X, &b_times_m_0);

    for(int i = 1; i < pk->l; i++) {
        ECP_BN462_copy(&B_i_times_m_i, &sig->B[i]);
        PAIR_BN462_G1mul(&B_i_times_m_i, message[i]);

        PAIR_BN462_ate(&inner_element, &pk->X, &B_i_times_m_i);
        PAIR_BN462_fexp(&inner_element);

        FP12_BN462_mul(&inner_product, &inner_element);
    }

    // Multiply the three
    FP12_BN462_copy(&lhs, &Xa_times_Xb);
    FP12_BN462_mul(&lhs, &inner_product);

    PAIR_BN462_ate(&rhs, &G2, &sig->c);
    PAIR_BN462_fexp(&rhs);

    res += FP12_BN462_equals(&lhs, &rhs);

    if (res == 4 ) return 1;

    return 0;
}