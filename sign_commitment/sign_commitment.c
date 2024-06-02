//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "sign_commitment.h"

#include <pair_BLS12381.h>
#include <params.h>

void
sign_commitment(schemeD_sig *sig, ECP_BLS12381 *commitment, schemeD_sk *sk, csprng *prng) {
    BIG_384_58 alpha;
    BIG_384_58_random(alpha, prng);

    ECP_BLS12381_generator(&sig->a);
    PAIR_BLS12381_G1mul(&sig->a, alpha);

    for(int i = 0; i < sk->l; i++) {
        ECP_BLS12381_copy(&sig->A[i], &sig->a);
        PAIR_BLS12381_G1mul(&sig->A[i], sk->z[i]);

        ECP_BLS12381_copy(&sig->B[i], &sig->A[i]);
        PAIR_BLS12381_G1mul(&sig->B[i], sk->y);
    }

    ECP_BLS12381_copy(&sig->b, &sig->a);
    PAIR_BLS12381_G1mul(&sig->b, sk->y);

    ECP_BLS12381 a_times_x;

    ECP_BLS12381_copy(&a_times_x, &sig->a);
    PAIR_BLS12381_G1mul(&a_times_x, sk->x);

    BIG_384_58 alpha_xy;
    BIG_384_58_one(alpha_xy);

    BIG_384_58_modmul(alpha_xy, alpha, sk->x, MODULUS);
    BIG_384_58_modmul(alpha_xy, alpha_xy, sk->y, MODULUS);

    ECP_BLS12381 M_times_alpha_xy;

    ECP_BLS12381_copy(&M_times_alpha_xy, commitment);

    PAIR_BLS12381_G1mul(&M_times_alpha_xy, alpha_xy);

    ECP_BLS12381_copy(&sig->c, &M_times_alpha_xy);
    ECP_BLS12381_add(&sig->c, &a_times_x);
}