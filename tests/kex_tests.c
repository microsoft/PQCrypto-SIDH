/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: benchmarking/testing isogeny-based key exchange
*
*********************************************************************************************/ 

#include "../SIDH.h"
#include "test_extras.h"
#include <malloc.h>
#include <stdio.h>


// Benchmark and test parameters  
#if defined(GENERIC_IMPLEMENTATION) 
    #define BENCH_LOOPS        5      // Number of iterations per bench 
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define BENCH_LOOPS       10       
    #define TEST_LOOPS        10      
#endif
#define BIGMONT_TEST_LOOPS    10      // Number of iterations per BigMont test

// Used in BigMont tests
static const uint64_t output1[12] = { 0x30E9AFA5BF75A92F, 0x88BC71EE9E221028, 0x999A50A9EE3B9A8E, 0x77E2934BD8D38B5A, 0x2668CAFC2933DB58, 0x457C65F7AD941041, 
                                      0x72EA3D5F92F33153, 0x6E04B56AF98D6285, 0x28FA680C091A9AE2, 0xE73DFE058AFD79ED, 0x902CD9E695BC7260, 0x00006FAC6F6E88AF };
static const uint64_t scalar1[12] = { 0x154A166BBD471DF4, 0xBF7CA3B41010FE6B, 0xC34BD28655936246, 0xAD8E8F394D3428B5, 0x275B1116E6B3BF08, 0x3C024A3CC03A6AFC,
                                      0x2300A0049FC615AF, 0xA0060FEC19263F0B, 0x69A1EB9091B8162C, 0xFDBE1DF28CDC03EE, 0xAA2030E6922EF3D5, 0x0000075E7401FA0E };


CRYPTO_STATUS cryptotest_kex(PCurveIsogenyStaticData CurveIsogenyData)
{ // Testing key exchange
    unsigned int i, pbytes = (CurveIsogenyData->pwordbits + 7)/8;   // Number of bytes in a field element 
    unsigned int obytes = (CurveIsogenyData->owordbits + 7)/8;      // Number of bytes in an element in [1, order]
    unsigned char *PrivateKeyA, *PrivateKeyB, *PublicKeyA, *PublicKeyB, *SharedSecretA, *SharedSecretB;
    PCurveIsogenyStruct CurveIsogeny = {0};
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed = true;
        
    // Allocating memory for private keys, public keys and shared secrets
    PrivateKeyA = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
    PrivateKeyB = (unsigned char*)calloc(1, obytes);
    PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);     // Three elements in GF(p^2)
    PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);
    SharedSecretA = (unsigned char*)calloc(1, 2*pbytes);    // One element in GF(p^2)  
    SharedSecretB = (unsigned char*)calloc(1, 2*pbytes);

    printf("\n\nTESTING EPHEMERAL ISOGENY-BASED KEY EXCHANGE \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve isogeny system: %s \n\n", CurveIsogenyData->CurveIsogeny);

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    for (i = 0; i < TEST_LOOPS; i++) 
    {
        Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);                            // Get some value as Alice's secret key and compute Alice's public key
        if (Status != CRYPTO_SUCCESS) {                                                  
            goto cleanup;
        } 

        Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);                            // Get some value as Bob's secret key and compute Bob's public key
        if (Status != CRYPTO_SUCCESS) {                                                  
            goto cleanup;
        }
    
        Status = EphemeralSecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecretA, CurveIsogeny);           // Alice computes her shared secret using Bob's public key
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    
        Status = EphemeralSecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB, CurveIsogeny);           // Bob computes his shared secret using Alice's public key
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }

        if (compare_words((digit_t*)SharedSecretA, (digit_t*)SharedSecretB, NBYTES_TO_NWORDS(2*pbytes)) != 0) {
            passed = false;
            Status = CRYPTO_ERROR_SHARED_KEY;
            break;
        }
    }

    if (passed == true) printf("  Key exchange tests ........................................... PASSED");
    else { printf("  Key exchange tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n"); 

cleanup:
    SIDH_curve_free(CurveIsogeny);    
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);    
    free(SharedSecretA);    
    free(SharedSecretB);

    return Status;
}


CRYPTO_STATUS cryptotest_kex_compress(PCurveIsogenyStaticData CurveIsogenyData)
{ // Compression tests
	unsigned int i;
	unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;    // Number of bytes in a field element 
	unsigned int obytes = (CurveIsogenyData->owordbits + 7)/8;    // Number of bytes in an element in [1, order]
	unsigned char *PrivateKeyA, *PublicKeyA, *PrivateKeyB, *PublicKeyB, *CompressedPKA, *CompressedPKB, *PublicKeyA_tmp, *PublicKeyB_tmp, *SharedSecretA, *SharedSecretB, *R, *A;
	PCurveIsogenyStruct CurveIsogeny = {0};
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	bool passed = true;

	// Allocating memory for private keys, public keys and shared secrets
	PrivateKeyA = (unsigned char*)calloc(1, obytes);                   // One element in [1, order]  
	PrivateKeyB = (unsigned char*)calloc(1, obytes);
	PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);                // Three elements in GF(p^2)
	PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);
	PublicKeyA_tmp = (unsigned char*)calloc(1, 3*2*pbytes);            // Three elements in GF(p^2)
	PublicKeyB_tmp = (unsigned char*)calloc(1, 3*2*pbytes);
	CompressedPKA = (unsigned char*)calloc(1, 3*obytes + 2*pbytes);    // Three elements in [1, order] plus one field element
	CompressedPKB = (unsigned char*)calloc(1, 3*obytes + 2*pbytes);
    SharedSecretA = (unsigned char*)calloc(1, 2*pbytes);               // One element in GF(p^2)  
    SharedSecretB = (unsigned char*)calloc(1, 2*pbytes);
    R = (unsigned char*)calloc(1, 2*2*pbytes);                         // One point in (X:Z) coordinates 
    A = (unsigned char*)calloc(1, 2*pbytes);                           // One element in GF(p^2)  

    printf("\n\nTESTING EPHEMERAL ISOGENY-BASED KEY EXCHANGE USING COMPRESSION \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve isogeny system: %s \n\n", CurveIsogenyData->CurveIsogeny);

	// Curve isogeny system initialization
	CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}
	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

    for (i = 0; i < TEST_LOOPS; i++) 
    {
        Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);                            // Get some value as Alice's secret key and compute Alice's public key
        if (Status != CRYPTO_SUCCESS) {                                                  
            goto cleanup;
        } 
        PublicKeyCompression_A(PublicKeyA, CompressedPKA, CurveIsogeny);                                     // Alice compresses her public key

        Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);                            // Get some value as Bob's secret key and compute Bob's public key
        if (Status != CRYPTO_SUCCESS) {                                                  
            goto cleanup;
        }
        PublicKeyCompression_B(PublicKeyB, CompressedPKB, CurveIsogeny);                                     // Bob compresses his public key

        PublicKeyBDecompression_A(PrivateKeyA, CompressedPKB, R, A, CurveIsogeny);                           // Alice decompresses Bob's public key data using her private key
        Status = EphemeralSecretAgreement_Compression_A(PrivateKeyA, R, A, SharedSecretA, CurveIsogeny);     // Alice computes her shared secret using decompressed Bob's public key data
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }  

        PublicKeyADecompression_B(PrivateKeyB, CompressedPKA, R, A, CurveIsogeny);                           // Bob decompresses Alice's public key data using his private key  
        Status = EphemeralSecretAgreement_Compression_B(PrivateKeyB, R, A, SharedSecretB, CurveIsogeny);     // Bob computes his shared secret using the decompressed Alice's public key data
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }  

        if (compare_words((digit_t*)SharedSecretA, (digit_t*)SharedSecretB, NBYTES_TO_NWORDS(2*pbytes)) != 0) {
            passed = false;
            Status = CRYPTO_ERROR_SHARED_KEY;
            break;
        }
	}
	if (passed == true) printf("  Key exchange tests using compression.......................... PASSED");
	else { printf("  Key exchange tests using compression... FAILED"); printf("\n"); goto cleanup; }
	printf("\n"); 

cleanup:
    SIDH_curve_free(CurveIsogeny);   
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);    
    free(PublicKeyA_tmp);    
    free(PublicKeyB_tmp);         
    free(CompressedPKA);    
    free(CompressedPKB); 
    free(SharedSecretA);    
    free(SharedSecretB);  
    free(R);    
    free(A); 

    return Status;
}


CRYPTO_STATUS cryptotest_BigMont(PCurveIsogenyStaticData CurveIsogenyData)
{ // Testing BigMont
    unsigned int i, j; 
    digit_t scalar[BIGMONT_NWORDS_ORDER] = {0};
    felm_t x = {0};
    PCurveIsogenyStruct CurveIsogeny = {0};
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed = true;

    printf("\n\nTESTING ELLIPTIC CURVE BIGMONT \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    copy_words((digit_t*)scalar1, scalar, BIGMONT_NWORDS_ORDER);    // Set scalar
    x[0] = 3;                                                       // Set initial x-coordinate

    for (i = 0; i < BIGMONT_TEST_LOOPS; i++)
    {
        for (j = 0; j < BIGMONT_NWORDS_ORDER-1; j++) {
            scalar[j] = (scalar[j] >> 1) | (scalar[j+1] << (RADIX-1));  
        }
        scalar[BIGMONT_NWORDS_ORDER-1] >>= 1;

        Status = BigMont_ladder((unsigned char*)x, scalar, (unsigned char*)x, CurveIsogeny);   
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }
    }

    if (compare_words((digit_t*)x, (digit_t*)output1, BIGMONT_NWORDS_ORDER) != 0) {
        passed = false;
        Status = CRYPTO_ERROR_SHARED_KEY;
    }

    if (passed == true) printf("  BigMont's scalar multiplication tests ........................ PASSED");
    else { printf("  BigMont's scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n"); 

cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}


CRYPTO_STATUS cryptorun_kex(PCurveIsogenyStaticData CurveIsogenyData)
{ // Benchmarking key exchange
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    unsigned char *PrivateKeyA, *PrivateKeyB, *PublicKeyA, *PublicKeyB, *SharedSecretA, *SharedSecretB;
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;
        
    // Allocating memory for private keys, public keys and shared secrets
    PrivateKeyA = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
    PrivateKeyB = (unsigned char*)calloc(1, obytes);
    PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);     // Three elements in GF(p^2)
    PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);
    SharedSecretA = (unsigned char*)calloc(1, 2*pbytes);    // One element in GF(p^2)  
    SharedSecretB = (unsigned char*)calloc(1, 2*pbytes);

    printf("\n\nBENCHMARKING EPHEMERAL ISOGENY-BASED KEY EXCHANGE \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve isogeny system: %s \n\n", CurveIsogenyData->CurveIsogeny);

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Benchmarking Alice's key generation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Alice's key generation runs in ............................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Alice's key generation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's key generation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Bob's key generation runs in ................................. %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Bob's key generation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Alice's shared key computation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = EphemeralSecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecretA, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Alice's shared key computation runs in ....................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Alice's shared key computation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's shared key computation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = EphemeralSecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Bob's shared key computation runs in ......................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Bob's shared key computation failed"); goto cleanup; } 
    printf("\n");

cleanup:
    SIDH_curve_free(CurveIsogeny);    
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);    
    free(SharedSecretA);    
    free(SharedSecretB);

    return Status;
}


CRYPTO_STATUS cryptorun_kex_compress(PCurveIsogenyStaticData CurveIsogenyData)
{ // Benchmarking key exchange with compression
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    unsigned char *PrivateKeyA, *PrivateKeyB, *PublicKeyA, *PublicKeyB, *CompressedPKA, *CompressedPKB, *SharedSecretA, *SharedSecretB, *R, *A;
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;
        
    // Allocating memory for private keys, public keys and shared secrets
    PrivateKeyA = (unsigned char*)calloc(1, obytes);                   // One element in [1, order]  
    PrivateKeyB = (unsigned char*)calloc(1, obytes);
    PublicKeyA = (unsigned char*)calloc(1, 3*2*pbytes);                // Three elements in GF(p^2)
    PublicKeyB = (unsigned char*)calloc(1, 3*2*pbytes);
    CompressedPKA = (unsigned char*)calloc(1, 3*obytes + 2*pbytes);    // Three elements in [1, order] and one field element  
    CompressedPKB = (unsigned char*)calloc(1, 3*obytes + 2*pbytes); 
    SharedSecretA = (unsigned char*)calloc(1, 2*pbytes);               // One element in GF(p^2)
    SharedSecretB = (unsigned char*)calloc(1, 2*pbytes); 
    R = (unsigned char*)calloc(1, 2*2*pbytes);                         // One point in (X:Z) coordinates 
    A = (unsigned char*)calloc(1, 2*pbytes);                           // One element in GF(p^2)             

    printf("\n\nBENCHMARKING EPHEMERAL ISOGENY-BASED KEY EXCHANGE USING COMPRESSION \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve isogeny system: %s \n\n", CurveIsogenyData->CurveIsogeny);

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    } 

    Status = EphemeralKeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny);    // Get some value as Alice's secret key and compute Alice's public key
    if (Status != CRYPTO_SUCCESS) {                                                  
        goto cleanup;
    }

    Status = EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);    // Get some value as Bob's secret key and compute Bob's public key
    if (Status != CRYPTO_SUCCESS) {                                                  
        goto cleanup;
    }

    // Benchmarking Alice's public key compression
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        PublicKeyCompression_A(PublicKeyA, CompressedPKA, CurveIsogeny);                   
        //if (Status != CRYPTO_SUCCESS) {                                                  
        //    passed = false;
        //    break;
        //}    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Alice's public key compression runs in ....................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Alice's public key compression failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Alice's key decompression
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        PublicKeyADecompression_B(PrivateKeyB, CompressedPKA, R, A, CurveIsogeny);    // Bob decompresses Alice's public key data using his private key  
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }                 
        //if (Status != CRYPTO_SUCCESS) {                                                  
        //    passed = false;
        //    break;
        //}    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Alice's public key decompression by Bob runs in .............. %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Alice's public key decompression by Bob failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's shared key computation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = EphemeralSecretAgreement_Compression_B(PrivateKeyB, R, A, SharedSecretB, CurveIsogeny);    // Bob computes his shared secret using the decompressed Alice's public key data
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Bob's shared key computation runs in ......................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Bob's shared key computation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's public key compression
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        PublicKeyCompression_B(PublicKeyB, CompressedPKB, CurveIsogeny);                    
        //if (Status != CRYPTO_SUCCESS) {                                                  
        //    passed = false;
        //    break;
        //}    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Bob's public key compression runs in ......................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Bob's public key compression failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's key decompression
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        PublicKeyBDecompression_A(PrivateKeyA, CompressedPKB, R, A, CurveIsogeny);    // Alice decompresses Bob's public key data using her private key                     
        //if (Status != CRYPTO_SUCCESS) {                                                  
        //    passed = false;
        //    break;
        //}    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Bob's public key decompression by Alice runs in .............. %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Bob's public key decompression by Alice failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Alice's shared key computation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = EphemeralSecretAgreement_Compression_A(PrivateKeyA, R, A, SharedSecretA, CurveIsogeny);    // Alice computes her shared secret using the decompressed Bob's public key data
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  Alice's shared key computation runs in ....................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  Alice's shared key computation failed"); goto cleanup; } 
    printf("\n");

cleanup:
    SIDH_curve_free(CurveIsogeny);   
    free(PrivateKeyA);    
    free(PrivateKeyB);    
    free(PublicKeyA);    
    free(PublicKeyB);         
    free(CompressedPKA);    
    free(CompressedPKB); 
    free(SharedSecretA);    
    free(SharedSecretB);  
    free(R);    
    free(A); 

    return Status;
}


CRYPTO_STATUS cryptorun_BigMont(PCurveIsogenyStaticData CurveIsogenyData)
{ // Benchmarking BigMont
    unsigned int i; 
    digit_t scalar[BIGMONT_NWORDS_ORDER] = {0};
    f2elm_t x = {0};
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    printf("\n\nBENCHMARKING ELLIPTIC CURVE BIGMONT \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    x[0][0] = 3;                                                    // Set initial x-coordinate
    
    passed = true;
    cycles = 0;
    for (i = 0; i < BENCH_LOOPS; i++)
    {        
        // Choose a random number in [1, BigMont_order-1] as scalar
        Status = random_BigMont_mod_order(scalar, CurveIsogeny);    
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }

        cycles1 = cpucycles();
        Status = BigMont_ladder((unsigned char*)x, scalar, (unsigned char*)x, CurveIsogeny);   
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }   
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) { printf("  BigMont's scalar multiplication runs in ...................... %10lld ", cycles/BENCH_LOOPS); print_unit; }
    else { printf("  BigMont's scalar multiplication failed"); goto cleanup; } 
    printf("\n");

cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}


int main()
{
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    
    Status = cryptotest_kex(&CurveIsogeny_SIDHp751);             // Test key exchange system "SIDHp751"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }

    Status = cryptorun_kex(&CurveIsogeny_SIDHp751);              // Benchmark key exchange system "SIDHp751"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }
    
    Status = cryptotest_kex_compress(&CurveIsogeny_SIDHp751);    // Test key exchange system "SIDHp751" using compression
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }

    Status = cryptorun_kex_compress(&CurveIsogeny_SIDHp751);     // Benchmark key exchange system "SIDHp751" using compression
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }
    
    Status = cryptotest_BigMont(&CurveIsogeny_SIDHp751);         // Test elliptic curve "BigMont"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }

    Status = cryptorun_BigMont(&CurveIsogeny_SIDHp751);          // Benchmark elliptic curve "BigMont"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }
    
    return true;
}