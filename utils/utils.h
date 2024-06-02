//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_UTILS_H
#define CL_SIGNATURES_UTILS_H

#include <big_464_60.h>
#include <fp12_BN462.h>

void BIG_464_60_mul_xyz(BIG_464_60 *res, BIG_464_60 x, BIG_464_60 y, BIG_464_60 z);

int pairing_and_equality_check(ECP2_BN462 *ecp2_point_1, ECP_BN462 *ecp_point_1, ECP2_BN462 *ecp2_point_2,
                               ECP_BN462 *ecp_point_2);

void two_element_pairing_and_multiplication(FP12_BN462 *res, ECP2_BN462 *ecp2_point_1, ECP_BN462 *ecp_point_1, ECP2_BN462 *ecp2_point_2,
                                            ECP_BN462 *ecp_point_2);

void three_element_pairing_and_multiplication(FP12_BN462 *res, ECP2_BN462 *ecp2_point_1, ECP_BN462 *ecp_point_1, ECP2_BN462 *ecp2_point_2,
                                ECP_BN462 *ecp_point_2, ECP2_BN462 *ecp2_point_3, ECP_BN462 *ecp_point_3);

#endif //CL_SIGNATURES_UTILS_H
