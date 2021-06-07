/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism
*********************************************************************************************/ 

#include "../src/random/random.h"

#ifdef DO_VALGRIND_CHECK
#include <valgrind/memcheck.h>
#endif

#ifdef DO_VALGRIND_CHECK
    #define TEST_LOOPS   1
#else 
#if defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) 
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define TEST_LOOPS        10      
#endif     
#endif

#if defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) 
    #define BENCH_LOOPS        5      // Number of iterations per bench 
#else
    #define BENCH_LOOPS      100    
#endif


int cryptotest_kem()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ss[CRYPTO_BYTES] = {0};
    unsigned char ss_[CRYPTO_BYTES] = {0};
    unsigned char bytes[4];
    uint32_t* pos = (uint32_t*)bytes;
    bool passed = true;

    #ifdef DO_VALGRIND_CHECK
        if (!RUNNING_ON_VALGRIND) {
            fprintf(stderr, "This test can only usefully be run inside valgrind.\n");
            fprintf(stderr, "valgrind sikexxx/test_KEM\n");
            exit(1);
        }
    #endif

    printf("\n\nTESTING ISOGENY-BASED KEY ENCAPSULATION MECHANISM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++) 
    {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss, pk);
        crypto_kem_dec(ss_, ct, sk);
#ifdef DO_VALGRIND_CHECK
        VALGRIND_MAKE_MEM_DEFINED(ss, CRYPTO_BYTES);
        VALGRIND_MAKE_MEM_DEFINED(ss_, CRYPTO_BYTES);
#endif
        
        if (memcmp(ss, ss_, CRYPTO_BYTES) != 0) {
            passed = false;
            break;
        }

        // Testing decapsulation after changing one bit of ct
        randombytes(bytes, 4);
        *pos %= CRYPTO_CIPHERTEXTBYTES;
        ct[*pos] ^= 1;
        crypto_kem_dec(ss_, ct, sk);
#ifdef DO_VALGRIND_CHECK
        VALGRIND_MAKE_MEM_DEFINED(ss, CRYPTO_BYTES);
        VALGRIND_MAKE_MEM_DEFINED(ss_, CRYPTO_BYTES);
#endif
        
        if (memcmp(ss, ss_, CRYPTO_BYTES) == 0) {
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
    unsigned long long cycles_keygen = 0, cycles_encaps = 0, cycles_decaps = 0, cycles1, cycles2;

    printf("\n\nBENCHMARKING ISOGENY-BASED KEY ENCAPSULATION MECHANISM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

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


int main(int argc, char **argv)
{
    int Status = PASSED;
    
    Status = cryptotest_kem(SYSTEM_NAME, TEST_LOOPS);  // Test key encapsulation mechanism
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n");
        return FAILED;
    }
    
    if ((argc > 1) && (strcmp("nobench", argv[1]) == 0)) {}
    else {
        Status = cryptorun_kem();                      // Benchmark key encapsulation mechanism
        if (Status != PASSED) {
            printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n");
            return FAILED;
        }
    }

    return Status;
}