//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "sign_commitment.h"

#include <pair_BN462.h>
#include <params.h>

void
sign_commitment(schemeD_sig *sig, ECP_BN462 *commitment, schemeD_sk *sk, csprng *prng) {
    BIG_464_60 alpha;
    BIG_464_60_random(alpha, prng);

    ECP_BN462_generator(&sig->a);
    PAIR_BN462_G1mul(&sig->a, alpha);

    for(int i = 0; i < sk->l; i++) {
        ECP_BN462_copy(&sig->A[i], &sig->a);
        PAIR_BN462_G1mul(&sig->A[i], sk->z[i]);

        ECP_BN462_copy(&sig->B[i], &sig->A[i]);
        PAIR_BN462_G1mul(&sig->B[i], sk->y);
    }

    ECP_BN462_copy(&sig->b, &sig->a);
    PAIR_BN462_G1mul(&sig->b, sk->y);

    ECP_BN462 a_times_x;

    ECP_BN462_copy(&a_times_x, &sig->a);
    PAIR_BN462_G1mul(&a_times_x, sk->x);

    BIG_464_60 alpha_xy;
    BIG_464_60_one(alpha_xy);

    BIG_464_60_modmul(alpha_xy, alpha, sk->x, MODULUS);
    BIG_464_60_modmul(alpha_xy, alpha_xy, sk->y, MODULUS);

    ECP_BN462 M_times_alpha_xy;

    ECP_BN462_copy(&M_times_alpha_xy, commitment);

    PAIR_BN462_G1mul(&M_times_alpha_xy, alpha_xy);

    ECP_BN462_copy(&sig->c, &M_times_alpha_xy);
    ECP_BN462_add(&sig->c, &a_times_x);
}