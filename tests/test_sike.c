/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism
*********************************************************************************************/ 


// Benchmark and test parameters  
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) 
    #define BENCH_LOOPS        5      // Number of iterations per bench 
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define BENCH_LOOPS       1000
    #define TEST_LOOPS        10      
#endif


int cryptotest_kem()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ss[CRYPTO_BYTES] = {0};
    unsigned char ss_[CRYPTO_BYTES] = {0};
    bool passed = true;

    printf("\n\nTESTING ISOGENY-BASED KEY ENCAPSULATION MECHANISM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++) 
    {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss, pk);
        crypto_kem_dec(ss_, ct, sk);
        
        if (memcmp(ss, ss_, CRYPTO_BYTES) != 0) {
            passed = false;
            break;
        }
    }

    if (passed == true) printf("  KEM tests .................................................... PASSED");
    else { printf("  KEM tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n"); 

    return PASSED;
}


int cryptorun_kem()
{ // Benchmarking key exchange
    unsigned int n;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ss[CRYPTO_BYTES] = {0};
    unsigned char ss_[CRYPTO_BYTES] = {0};
    unsigned long long cycles_keygen, cycles_encaps, cycles_decaps, cycles1, cycles2;

    printf("\n\nBENCHMARKING ISOGENY-BASED KEY ENCAPSULATION MECHANISM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");


    cycles_keygen = 0;
    cycles_encaps = 0;
    cycles_decaps = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        // Benchmarking key generation
        cycles1 = cpucycles();
        crypto_kem_keypair(pk, sk);
        cycles2 = cpucycles();
        cycles_keygen = cycles_keygen+(cycles2-cycles1);
        
        // Benchmarking encapsulation    
        cycles1 = cpucycles();
        crypto_kem_enc(ct, ss, pk);
        cycles2 = cpucycles();
        cycles_encaps = cycles_encaps+(cycles2-cycles1);

        // Benchmarking decapsulation
        cycles1 = cpucycles();
        crypto_kem_dec(ss_, ct, sk);   
        cycles2 = cpucycles();
        cycles_decaps = cycles_decaps+(cycles2-cycles1);
    }

    printf("  Key generation runs in ....................................... %10lld ", cycles_keygen/BENCH_LOOPS); print_unit;
    printf("\n");
    printf("  Encapsulation runs in ........................................ %10lld ", cycles_encaps/BENCH_LOOPS); print_unit;
    printf("\n");        
    printf("  Decapsulation runs in ........................................ %10lld ", cycles_decaps/BENCH_LOOPS); print_unit;
    printf("\n");

    return PASSED;
}


int main()
{
    int Status = PASSED;
    
    Status = cryptotest_kem();             // Test key encapsulation mechanism
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }

    Status = cryptorun_kem();              // Benchmark key encapsulation mechanism
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }

    return Status;
}