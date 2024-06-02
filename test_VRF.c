#include <commitment_schemes/PoK_message/PoK_message.h>
#include <bls_BN462.h>
#include <signatures/schemeD/schemeD.h>
#include <sign_commitment/sign_commitment.h>
#include <ecdh_BN462.h>
#include <commitment_schemes/PoK_signature/PoK_signature.h>
#include <utils/utils.h>
#include "assert.h"
#include <stdio.h>
#include <time.h>
#include <ecp_BN462.h>
#include <pair_BN462.h>
#include <time.h>

void printDuration(clock_t start, clock_t end, char* msg) {
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("%s: %.3f milliseconds\n", msg, cpu_time_used);
}

void test(csprng *prng) {
    BIG_464_60 x;
    BIG_464_60 s;
    ECP_BN462 g;
    ECP2_BN462 g2;
    BIG_464_60 SK;
    ECP_BN462 PK;

    // Input
    BIG_464_60_random(x, prng);

    // KeyGen
    clock_t a = clock();
    BIG_464_60_random(s, prng);
    ECP_BN462_generator(&g);
    ECP2_BN462_generator(&g2);
    BIG_464_60_copy(SK, s);
    ECP_BN462_copy(&PK, &g);
    PAIR_BN462_G1mul(&PK, SK);
    clock_t b = clock();
    printDuration(a, b, "KeyGen");

    // Prove
    FP12_BN462 e_g_g2;
    FP12_BN462 e_g_g2_mul;
    BIG_464_60 x_SK;
    FP12_BN462 F_SK_x;
    ECP2_BN462 Pi_SK_x;
    PAIR_BN462_ate(&e_g_g2, &g2, &g);
    PAIR_BN462_fexp(&e_g_g2);
    BIG_464_60_add(x_SK, x, SK);
    FP12_BN462_copy(&e_g_g2_mul, &e_g_g2);
    PAIR_BN462_GTpow(&e_g_g2_mul, x_SK);
    FP12_BN462_inv(&F_SK_x, &e_g_g2_mul);
    ECP2_BN462_copy(&Pi_SK_x, &g2);
    PAIR_BN462_G2mul(&Pi_SK_x, x_SK);
    ECP2_BN462_neg(&Pi_SK_x);
    clock_t c = clock();
    printDuration(b, c, "Prove");

    // Verify
    ECP_BN462 g_x_PK;
    FP12_BN462 e_pi;
    FP12_BN462 e_g_pi;
    int check1, check2;
    ECP_BN462_copy(&g_x_PK, &g);
    PAIR_BN462_G1mul(&g_x_PK, x);
    ECP_BN462_add(&g_x_PK, &PK);
    PAIR_BN462_ate(&e_pi, &Pi_SK_x, &g_x_PK);
    PAIR_BN462_fexp(&e_pi);
    PAIR_BN462_ate(&e_g_g2, &g2, &g);
    PAIR_BN462_fexp(&e_g_g2);
    check1 = FP12_BN462_equals(&e_pi, &e_g_g2);
    
    PAIR_BN462_ate(&e_g_pi, &Pi_SK_x, &g);
    PAIR_BN462_fexp(&e_g_pi);
    check2 = FP12_BN462_equals(&F_SK_x, &e_g_pi);

    printf("check1 %d check2 %d\n", check1, check2);
    clock_t d = clock();
    printDuration(c, d, "Verify");

    return 0;

}

int main() {

    //---------------------------------------------------
    // Init
    //---------------------------------------------------
    if(BLS_BN462_INIT() != BLS_OK) {
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