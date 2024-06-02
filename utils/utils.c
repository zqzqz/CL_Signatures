//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include <ecp_BLS12381.h>
#include <pair_BLS12381.h>
#include "utils.h"

void BIG_384_58_mul_xyz(BIG_384_58 *res, BIG_384_58 x, BIG_384_58 y, BIG_384_58 z) {
    BIG_384_58_modmul(*res, x, y, (int64_t *)CURVE_Order_BLS12381);
    BIG_384_58_modmul(*res, *res, z, (int64_t *)CURVE_Order_BLS12381);
}

int pairing_and_equality_check(ECP2_BLS12381 *ecp2_point_1, ECP_BLS12381 *ecp_point_1, ECP2_BLS12381 *ecp2_point_2,
                               ECP_BLS12381 *ecp_point_2) {
    FP12_BLS12381 p1, p2;

    PAIR_BLS12381_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BLS12381_fexp(&p1);

    PAIR_BLS12381_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BLS12381_fexp(&p2);

    return FP12_BLS12381_equals(&p1, &p2);
}

void two_element_pairing_and_multiplication(FP12_BLS12381 *res, ECP2_BLS12381 *ecp2_point_1, ECP_BLS12381 *ecp_point_1, ECP2_BLS12381 *ecp2_point_2,
                                            ECP_BLS12381 *ecp_point_2) {

    FP12_BLS12381 p1, p2;

    PAIR_BLS12381_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BLS12381_fexp(&p1);

    PAIR_BLS12381_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BLS12381_fexp(&p2);

    FP12_BLS12381_copy(res, &p1);
    FP12_BLS12381_mul(res, &p2);
}

void three_element_pairing_and_multiplication(FP12_BLS12381 *res, ECP2_BLS12381 *ecp2_point_1, ECP_BLS12381 *ecp_point_1, ECP2_BLS12381 *ecp2_point_2,
                                              ECP_BLS12381 *ecp_point_2, ECP2_BLS12381 *ecp2_point_3, ECP_BLS12381 *ecp_point_3) {

    FP12_BLS12381 p1, p2, p3;

    PAIR_BLS12381_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BLS12381_fexp(&p1);

    PAIR_BLS12381_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BLS12381_fexp(&p2);

    PAIR_BLS12381_ate(&p3, ecp2_point_3, ecp_point_3);
    PAIR_BLS12381_fexp(&p3);

    FP12_BLS12381_copy(res, &p1);
    FP12_BLS12381_mul(res, &p2);
    FP12_BLS12381_mul(res, &p3);
}
