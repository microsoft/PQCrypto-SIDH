/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
* Copyright (c) Microsoft Corporation
*
* Website: https://github.com/microsoft/PQCrypto-SIDH
* Released under MIT license
*
* Abstract: benchmarking/testing isogeny-based key exchange
*********************************************************************************************/ 


// Benchmark and test parameters  
#if defined(GENERIC_IMPLEMENTATION) || (OS_TARGET == OS_WIN) || (TARGET == TARGET_ARM)
    #define BENCH_LOOPS        5      // Number of iterations per bench 
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define BENCH_LOOPS     1000       
    #define TEST_LOOPS        10      
#endif


int cryptotest_kex()
{ // Testing key exchange
    unsigned int i;
    unsigned char PrivateKeyA[SIDH_SECRETKEYBYTES_A], PrivateKeyB[SIDH_SECRETKEYBYTES_B];
    unsigned char PublicKeyA[SIDH_PUBLICKEYBYTES], PublicKeyB[SIDH_PUBLICKEYBYTES];
    unsigned char SharedSecretA[SIDH_BYTES], SharedSecretB[SIDH_BYTES];
    bool passed = true;

    printf("\n\nTESTING EPHEMERAL ISOGENY-BASED KEY EXCHANGE SYSTEM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++) 
    {
        random_mod_order_A(PrivateKeyA);
        random_mod_order_B(PrivateKeyB);

        EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA);                            // Get some value as Alice's secret key and compute Alice's public key
        EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB);                            // Get some value as Bob's secret key and compute Bob's public key
        EphemeralSecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecretA);           // Alice computes her shared secret using Bob's public key
        EphemeralSecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB);           // Bob computes his shared secret using Alice's public key
        
        if (memcmp(SharedSecretA, SharedSecretB, SIDH_BYTES) != 0) {
            passed = false;
            break;
        }
    }

    if (passed == true) printf("  Key exchange tests ........................................... PASSED");
    else { printf("  Key exchange tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n"); 

    return PASSED;
}


int cryptorun_kex()
{ // Benchmarking key exchange
    unsigned int n;
    unsigned char PrivateKeyA[SIDH_SECRETKEYBYTES_A], PrivateKeyB[SIDH_SECRETKEYBYTES_B];
    unsigned char PublicKeyA[SIDH_PUBLICKEYBYTES], PublicKeyB[SIDH_PUBLICKEYBYTES];
    unsigned char SharedSecretA[SIDH_BYTES], SharedSecretB[SIDH_BYTES];
    unsigned long long cycles_keygen_A = 0, cycles_keygen_B = 0, cycles_shared_A = 0, cycles_shared_B = 0, cycles1, cycles2;

    printf("\n\nBENCHMARKING EPHEMERAL ISOGENY-BASED KEY EXCHANGE SYSTEM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    random_mod_order_A(PrivateKeyA);
    random_mod_order_B(PrivateKeyB);

    for (n = 0; n < BENCH_LOOPS; n++)
    {
        // Benchmarking Alice's key generation
        cycles1 = cpucycles();
        EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA);
        cycles2 = cpucycles();
        cycles_keygen_A = cycles_keygen_A+(cycles2-cycles1);

        // Benchmarking Bob's key generation
        cycles1 = cpucycles();
        EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB);
        cycles2 = cpucycles();
        cycles_keygen_B = cycles_keygen_B+(cycles2-cycles1);

        // Benchmarking Alice's shared key computation
        cycles1 = cpucycles();
        EphemeralSecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecretA); 
        cycles2 = cpucycles();
        cycles_shared_A = cycles_shared_A+(cycles2-cycles1);

        // Benchmarking Bob's shared key computation
        cycles1 = cpucycles();
        EphemeralSecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB);
        cycles2 = cpucycles();
        cycles_shared_B = cycles_shared_B+(cycles2-cycles1);
    }

    printf("  Alice's key generation runs in ............................... %10lld ", cycles_keygen_A/BENCH_LOOPS); print_unit;
    printf("\n");
    printf("  Bob's key generation runs in ................................. %10lld ", cycles_keygen_B/BENCH_LOOPS); print_unit;
    printf("\n");
    printf("  Alice's shared key computation runs in ....................... %10lld ", cycles_shared_A/BENCH_LOOPS); print_unit;
    printf("\n");
    printf("  Bob's shared key computation runs in ......................... %10lld ", cycles_shared_B/BENCH_LOOPS); print_unit;
    printf("\n");

    return PASSED;
}


int main()
{
    int Status = PASSED;
    
    Status = cryptotest_kex();             // Test key exchange
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEX_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }

    Status = cryptorun_kex();              // Benchmark key exchange
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEX_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }
    
    return Status;
}