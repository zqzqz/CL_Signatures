//
// Created by Alexandros Hasikos on 09/07/2021.
//

#include <core.h>
#include <bls_BN254.h>
#include <string.h>

#include "signatures/schemeD/schemeD.h"
#include "signatures/schemeC/schemeC.h"
#include "signatures/schemeA/schemeA.h"
#include "signatures/schemeB/schemeB.h"

void test_scheme_A(csprng *prng) {
    schemeA_sk sk;
    schemeA_pk pk;
    schemeA_sig sig;

    schemeA_generate_sk(&sk, prng);

    schemeA_generate_pk(&pk, &sk);

    BIG_256_56 message;
    BIG_256_56_random(message, prng);

    schemeA_sign(&sig, message, &sk, prng);

    if(schemeA_verify(&sig, message, &pk)) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }
}

void test_scheme_B(csprng *prng) {
    schemeB_sk sk;
    schemeB_pk pk;
    schemeB_sig sig;

    schemeB_generate_sk(&sk, prng);

    schemeB_generate_pk(&pk, &sk);

    BIG_256_56 message, randomness;

    BIG_256_56_random(message, prng);
    BIG_256_56_random(randomness, prng);

    schemeB_sign(&sig, message, randomness, &sk, prng);

    if(schemeB_verify(&sig, message, randomness, &pk)) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }
}

void test_scheme_C(csprng *prng) {
    const uint32_t number_of_messages = 32;
    int res = 1;

    BIG_256_56 message[number_of_messages];
    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    schemeC_sk sk;
    schemeC_pk pk;

    schemeC_init_keypair(&sk, &pk, number_of_messages);
    schemeC_generate_sk(&sk, prng);
    schemeC_generate_pk(&pk, &sk);

    schemeC_sig sig;
    schemeC_init_signature(&sig, number_of_messages);

    schemeC_sign(&sig, message, &sk, prng);

    if(! schemeC_verify(&sig, message, &pk)) res = 0;

    //Negative test change message to 0
    memset(message, 0, number_of_messages * (sizeof(BIG_256_56)));
    if(schemeC_verify(&sig, message, &pk)) res = 0;

    res ? printf("Success\n") : printf("Failure\n");

    schemeC_destroy_keypair(&sk, &pk);
    schemeC_destroy_signature(&sig);
}

void test_scheme_D(csprng *prng) {
    const uint32_t number_of_messages = 32;
    int res = 1;

    BIG_256_56 message[number_of_messages];
    for(int i = 0; i < number_of_messages; i++) {
        BIG_256_56_random(message[i], prng);
    }

    schemeD_sk sk;
    schemeD_pk pk;

    schemeD_init_keypair(&sk, &pk, number_of_messages);
    schemeD_generate_sk(&sk, prng);
    schemeD_generate_pk(&pk, &sk);

    schemeD_sig sig;
    schemeD_init_signature(&sig, number_of_messages);

    schemeD_sign(&sig, message, &sk, prng);

    if(! schemeD_verify(&sig, message, &pk)) res = 0;

    //Negative test change message to 0
    memset(message, 0, number_of_messages * (sizeof(BIG_256_56)));
    if(schemeD_verify(&sig, message, &pk)) res = 0;

    res ? printf("Success\n") : printf("Failure\n");

    schemeD_destroy_keypair(&sk, &pk);
    schemeD_destroy_signature(&sig);
}

int main() {

    //---------------------------------------------------
    // Init
    //---------------------------------------------------
    if(BLS_BN254_INIT() != BLS_OK) {
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

    printf("Testing Scheme A...");
    test_scheme_A(&prng);

    printf("Testing Scheme B...");
    test_scheme_B(&prng);

    printf("Testing Scheme C...");
    test_scheme_C(&prng);

    printf("Testing Scheme D...");
    test_scheme_D(&prng);


    return 0;

}
