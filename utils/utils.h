//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_UTILS_H
#define CL_SIGNATURES_UTILS_H

#include <big_384_58.h>
#include <fp12_BLS12381.h>

void BIG_384_58_mul_xyz(BIG_384_58 *res, BIG_384_58 x, BIG_384_58 y, BIG_384_58 z);

int pairing_and_equality_check(ECP2_BLS12381 *ecp2_point_1, ECP_BLS12381 *ecp_point_1, ECP2_BLS12381 *ecp2_point_2,
                               ECP_BLS12381 *ecp_point_2);

void two_element_pairing_and_multiplication(FP12_BLS12381 *res, ECP2_BLS12381 *ecp2_point_1, ECP_BLS12381 *ecp_point_1, ECP2_BLS12381 *ecp2_point_2,
                                            ECP_BLS12381 *ecp_point_2);

void three_element_pairing_and_multiplication(FP12_BLS12381 *res, ECP2_BLS12381 *ecp2_point_1, ECP_BLS12381 *ecp_point_1, ECP2_BLS12381 *ecp2_point_2,
                                ECP_BLS12381 *ecp_point_2, ECP2_BLS12381 *ecp2_point_3, ECP_BLS12381 *ecp_point_3);

#endif //CL_SIGNATURES_UTILS_H
