//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include <ecp_BN462.h>
#include <pair_BN462.h>
#include "utils.h"

void BIG_464_60_mul_xyz(BIG_464_60 *res, BIG_464_60 x, BIG_464_60 y, BIG_464_60 z) {
    BIG_464_60_modmul(*res, x, y, (int64_t *)CURVE_Order_BN462);
    BIG_464_60_modmul(*res, *res, z, (int64_t *)CURVE_Order_BN462);
}

int pairing_and_equality_check(ECP2_BN462 *ecp2_point_1, ECP_BN462 *ecp_point_1, ECP2_BN462 *ecp2_point_2,
                               ECP_BN462 *ecp_point_2) {
    FP12_BN462 p1, p2;

    PAIR_BN462_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BN462_fexp(&p1);

    PAIR_BN462_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BN462_fexp(&p2);

    return FP12_BN462_equals(&p1, &p2);
}

void two_element_pairing_and_multiplication(FP12_BN462 *res, ECP2_BN462 *ecp2_point_1, ECP_BN462 *ecp_point_1, ECP2_BN462 *ecp2_point_2,
                                            ECP_BN462 *ecp_point_2) {

    FP12_BN462 p1, p2;

    PAIR_BN462_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BN462_fexp(&p1);

    PAIR_BN462_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BN462_fexp(&p2);

    FP12_BN462_copy(res, &p1);
    FP12_BN462_mul(res, &p2);
}

void three_element_pairing_and_multiplication(FP12_BN462 *res, ECP2_BN462 *ecp2_point_1, ECP_BN462 *ecp_point_1, ECP2_BN462 *ecp2_point_2,
                                              ECP_BN462 *ecp_point_2, ECP2_BN462 *ecp2_point_3, ECP_BN462 *ecp_point_3) {

    FP12_BN462 p1, p2, p3;

    PAIR_BN462_ate(&p1, ecp2_point_1, ecp_point_1);
    PAIR_BN462_fexp(&p1);

    PAIR_BN462_ate(&p2, ecp2_point_2, ecp_point_2);
    PAIR_BN462_fexp(&p2);

    PAIR_BN462_ate(&p3, ecp2_point_3, ecp_point_3);
    PAIR_BN462_fexp(&p3);

    FP12_BN462_copy(res, &p1);
    FP12_BN462_mul(res, &p2);
    FP12_BN462_mul(res, &p3);
}
