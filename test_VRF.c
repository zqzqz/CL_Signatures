#include <commitment_schemes/PoK_message/PoK_message.h>
#include <bls_BLS12381.h>
#include <signatures/schemeD/schemeD.h>
#include <sign_commitment/sign_commitment.h>
#include <ecdh_BLS12381.h>
#include <commitment_schemes/PoK_signature/PoK_signature.h>
#include <utils/utils.h>
#include "assert.h"
#include <stdio.h>
#include <time.h>
#include <ecp_BLS12381.h>
#include <pair_BLS12381.h>
#include <time.h>

void printDuration(clock_t start, clock_t end, char* msg) {
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("%s: %.3f milliseconds\n", msg, cpu_time_used);
}

void test(csprng *prng) {
    BIG_384_58 x;
    BIG_384_58 s;
    ECP_BLS12381 g;
    ECP2_BLS12381 g2;
    BIG_384_58 SK;
    ECP_BLS12381 PK;

    // Input
    BIG_384_58_random(x, prng);

    // KeyGen
    clock_t a = clock();
    BIG_384_58_random(s, prng);
    ECP_BLS12381_generator(&g);
    ECP2_BLS12381_generator(&g2);
    BIG_384_58_copy(SK, s);
    ECP_BLS12381_copy(&PK, &g);
    PAIR_BLS12381_G1mul(&PK, SK);
    clock_t b = clock();
    printDuration(a, b, "KeyGen");

    // Prove
    FP12_BLS12381 e_g_g2;
    FP12_BLS12381 e_g_g2_mul;
    BIG_384_58 x_SK;
    FP12_BLS12381 F_SK_x;
    ECP2_BLS12381 Pi_SK_x;
    PAIR_BLS12381_ate(&e_g_g2, &g2, &g);
    PAIR_BLS12381_fexp(&e_g_g2);
    BIG_384_58_add(x_SK, x, SK);
    FP12_BLS12381_copy(&e_g_g2_mul, &e_g_g2);
    PAIR_BLS12381_GTpow(&e_g_g2_mul, x_SK);
    FP12_BLS12381_inv(&F_SK_x, &e_g_g2_mul);
    ECP2_BLS12381_copy(&Pi_SK_x, &g2);
    PAIR_BLS12381_G2mul(&Pi_SK_x, x_SK);
    ECP2_BLS12381_neg(&Pi_SK_x);
    clock_t c = clock();
    printDuration(b, c, "Prove");

    // Verify
    ECP_BLS12381 g_x_PK;
    FP12_BLS12381 e_pi;
    FP12_BLS12381 e_g_pi;
    int check1, check2;
    ECP_BLS12381_copy(&g_x_PK, &g);
    PAIR_BLS12381_G1mul(&g_x_PK, x);
    ECP_BLS12381_add(&g_x_PK, &PK);
    PAIR_BLS12381_ate(&e_pi, &Pi_SK_x, &g_x_PK);
    PAIR_BLS12381_fexp(&e_pi);
    PAIR_BLS12381_ate(&e_g_g2, &g2, &g);
    PAIR_BLS12381_fexp(&e_g_g2);
    check1 = FP12_BLS12381_equals(&e_pi, &e_g_g2);
    
    PAIR_BLS12381_ate(&e_g_pi, &Pi_SK_x, &g);
    PAIR_BLS12381_fexp(&e_g_pi);
    check2 = FP12_BLS12381_equals(&F_SK_x, &e_g_pi);

    printf("check1 %d check2 %d\n", check1, check2);
    clock_t d = clock();
    printDuration(c, d, "Verify");

    return 0;

}

int main() {

    //---------------------------------------------------
    // Init
    //---------------------------------------------------
    if(BLS_BLS12381_INIT() != BLS_OK) {
        printf("Error\n");
        exit(1);
    }
    //---------------------------------------------------


    //---------------------------------------------------
    // Declare and seed prng
    //---------------------------------------------------
    char seed[20] = {0};
    csprng prng;

    RAND_seed(&prng, sizeof(seed), seed);
    //---------------------------------------------------

    for (int i = 0; i < 1000; i++) {
        test(&prng);
    }

    return 1;
}