//
// Created by Alexandros Hasikos on 21/07/2021.
//

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

#define NUMBER_OF_MESSAGES 2

void printDuration(clock_t start, clock_t end, char* msg) {
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000;
    printf("%s: %.3f milliseconds\n", msg, cpu_time_used);
}

void create_key_pair(schemeD_sk *sk, schemeD_pk *pk, csprng *prng, uint32_t n) {
    schemeD_init_keypair(sk, pk, n);
    schemeD_generate_sk(sk, prng);
    schemeD_generate_pk(pk, sk);
}

int execute_PoK_of_message_protocol_and_obtain_signature(schemeD_sig *sig, BIG_384_58 *message, schemeD_pk *user_pk,
                                                         schemeD_sk *user_sk, schemeD_sk *signer_sk, csprng *prng) {
    BIG_384_58 challenge, t[NUMBER_OF_MESSAGES], s[NUMBER_OF_MESSAGES];
    ECP2_BLS12381 T, commitment;

    clock_t a = clock();
    generate_commitment(&commitment, message, user_pk);

    //Prover(Compute T) -> Verifier
    prover_1(&T, t, user_pk, prng);

    //Compute challenge
    BIG_384_58_random(challenge, prng);

    //Prover(Compute s based on challenge) -> Verifier
    prover_2(s, challenge, t, message, NUMBER_OF_MESSAGES);
    clock_t b = clock();
    printDuration(a, b, "RSU generate zkp");

    //Verifier(Given T, commitment and s verify PoK) -> 1 or 0
    assert(verifier(&T, &commitment, s, challenge, user_pk));
    clock_t c = clock();
    printDuration(b, c, "Bank verify zkp");

    ECP_BLS12381 converted_commitment;

    commitment_conversion(&converted_commitment, user_sk, sig, message);

    sign_commitment(sig, &converted_commitment, signer_sk, prng);
    clock_t d = clock();
    printDuration(c, d, "Bank sign");

    return 1;
}

void compute_blind_signature(schemeD_sig *blind_sig, schemeD_sig *sig, PoK_randomness *randomness, csprng *prng) {
    clock_t a = clock();
    PoK_compute_blind_signature(blind_sig, sig, randomness, prng);
    clock_t b = clock();
    printDuration(a, b, "Bank sign2");
}

int execute_PoK_of_signature_and_verify_pairings(schemeD_sig *sig, schemeD_pk *pk, PoK_randomness *randomness,
                                                 BIG_384_58 *message, csprng *prng) {

    clock_t a = clock();
    FP12_BLS12381 commitment;

    PoK_generate_commitment(&commitment, randomness, message, pk, sig);

    FP12_BLS12381 T;
    BIG_384_58 t1, t2[NUMBER_OF_MESSAGES], s1, s2[NUMBER_OF_MESSAGES], challenge;

    //Generate T
    PoK_prover_1(&T, t1, t2, pk, sig, prng);

    //Generate challenge
    BIG_384_58_random(challenge, prng);

    //Generate s1, s1
    PoK_prover_2(s1, s2, challenge, t1, t2, message, randomness, sig);
    clock_t b = clock();
    printDuration(a, b, "RSU generate sig zkp");

    //Verify randomness
    assert(PoK_verifier(s1, s2, challenge, &T, &commitment, pk, sig));

    //Verify pairings
    assert(PoK_verify_pairings(sig, pk));
    clock_t c = clock();
    printDuration(b, c, "Vehicle verify sig zkp");

    return 1;
}

void test_anonymous_credentials(csprng *prng) {

    BIG_384_58 message[NUMBER_OF_MESSAGES], t[NUMBER_OF_MESSAGES], s[NUMBER_OF_MESSAGES], challenge_1;

    BIG_384_58_random(challenge_1, prng);

    for(int i = 0; i < NUMBER_OF_MESSAGES; i++) {
        BIG_384_58_random(message[i], prng);
    }

    //User key pair
    schemeD_sk user_sk;
    schemeD_pk user_pk;
    create_key_pair(&user_sk, &user_pk, prng, NUMBER_OF_MESSAGES);


    //Signer key pair
    schemeD_sk signer_sk;
    schemeD_pk signer_pk;
    create_key_pair(&signer_sk, &signer_pk, prng, NUMBER_OF_MESSAGES);

    //Execute PoK of message protocol and obtain signature
    schemeD_sig sig, blind_sig;
    schemeD_init_signature(&sig, NUMBER_OF_MESSAGES);
    schemeD_init_signature(&blind_sig, NUMBER_OF_MESSAGES);

    assert(execute_PoK_of_message_protocol_and_obtain_signature(&sig, message, &user_pk, &user_sk, &signer_sk, prng));

    PoK_randomness randomness;
    BIG_384_58_random(randomness.r, prng);

    compute_blind_signature(&blind_sig, &sig, &randomness, prng);

    assert(execute_PoK_of_signature_and_verify_pairings(&blind_sig, &signer_pk, &randomness, message, prng));// ? res++ : (res = 0);

    schemeD_destroy_keypair(&user_sk, &user_pk);
    schemeD_destroy_keypair(&signer_sk, &signer_pk);
    schemeD_destroy_signature(&sig);

    printf("Success\n");
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


    printf("Testing anonymous credentials...\n");
    for (int i = 0; i < 1000; i++) {
        test_anonymous_credentials(&prng);
    }

    return 0;
}
