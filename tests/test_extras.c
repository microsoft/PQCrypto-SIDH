/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: utility functions for testing and benchmarking
*
*********************************************************************************************/


#include "../SIDH_internal.h"
#include "test_extras.h"
#if (OS_TARGET == OS_WIN)
    #include <windows.h>
    #include <intrin.h>
#endif
#if (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
    #include <time.h>
#endif
#include <stdlib.h>


// Global constants          
extern const uint64_t p751[NWORDS_FIELD];
extern const uint64_t Montgomery_R2[NWORDS_FIELD]; 

// Montgomery constant -p751^-1 mod 2^768
static uint64_t Montgomery_pp751[NWORDS_FIELD] = { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xEEB0000000000000, 
                                                   0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x258C28E5D541F71C };   


int64_t cpucycles(void)
{ // Access system counter for benchmarking
#if (OS_TARGET == OS_WIN) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    return __rdtsc();
#elif (OS_TARGET == OS_WIN) && (TARGET == TARGET_ARM)
    return __rdpmccntr64();
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
    struct timespec time;

    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)(time.tv_sec*1e9 + time.tv_nsec);
#else
    return 0;            
#endif
}


CRYPTO_STATUS random_bytes_test(unsigned int nbytes, unsigned char* random_array)
{ // Generate "nbytes" random bytes and output the result to random_array
  // Returns CRYPTO_SUCCESS (=1) on success, CRYPTO_ERROR (=0) otherwise.
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    unsigned int i;

    if (nbytes == 0) {
        return CRYPTO_ERROR;
    }

    for (i = 0; i < nbytes; i++) {
        *(random_array + i) = (unsigned char)rand();    // nbytes of random values
    }

    return CRYPTO_SUCCESS;
}


int compare_words(digit_t* a, digit_t* b, unsigned int nwords)
{ // Comparing "nword" elements, a=b? : (1) a!=b, (0) a=b
  // SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
    unsigned int i;

    for (i = 0; i < nwords; i++)
    {
        if (a[i] != b[i]) return 1;
    }

    return 0; 
}



static __inline void sub751_test(felm_t a, felm_t b, felm_t c)
{ // 751-bit subtraction without borrow, c = a-b where a>b
  // SECURITY NOTE: this function does not have constant-time execution. It is for TESTING ONLY.     
    unsigned int i;
    digit_t res, carry, borrow = 0;
  
    for (i = 0; i < NWORDS_FIELD; i++)
    {
        res = a[i] - b[i];
        carry = (a[i] < b[i]);
        c[i] = res - borrow;
        borrow = carry || (res < borrow);
    } 

    return;
}


void fprandom751_test(felm_t a)
{ // Generating a pseudo-random field element in [0, p751-1] 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.
    int i, diff = 768-751;
    unsigned char* string = NULL;

    string = (unsigned char*)a;
    for (i = 0; i < sizeof(digit_t)*NWORDS_FIELD; i++) {
        *(string + i) = (unsigned char)rand();              // Obtain 768-bit number
    }
    a[NWORDS_FIELD-1] &= (((digit_t)(-1) << diff) >> diff);

    while (fpcompare751((digit_t*)p751, a) < 1) {           // Force it to [0, modulus-1]
        sub751_test(a, (digit_t*)p751, a);
    }

    return;
}


void fp2random751_test(f2elm_t a)
{ // Generating a pseudo-random element in GF(p751^2) 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.

    fprandom751_test(a[0]);
    fprandom751_test(a[1]);
}


int fpcompare751(felm_t a, felm_t b)
{ // Comparing two field elements, a=b? : (1) a>b, (0) a=b, (-1) a<b
  // SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
    int i;

    for (i = NWORDS_FIELD-1; i >= 0; i--)
    {
        if (a[i] > b[i]) return 1;
        else if (a[i] < b[i]) return -1;
    }

    return 0; 
}


int fp2compare751(f2elm_t a, f2elm_t b)
{ // Comparing two quadratic extension field elements, ai=bi? : (1) ai!=bi, (0) ai=bi
  // SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.

    if (fpcompare751(a[0], b[0])!=0 || fpcompare751(a[1], b[1])!=0) return 1;
    return 0; 
}


static __inline void mp_mul_basic(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)                   
{ // Multiprecision schoolbook multiprecision multiply, c = a*b, where lng(a) = lng(b) = nwords.   
    unsigned int i, j;
    digit_t u, v, UV[2];
    unsigned int carry = 0;

     for (i = 0; i < (2*nwords); i++) c[i] = 0;

     for (i = 0; i < nwords; i++) {
          u = 0;
          for (j = 0; j < nwords; j++) {
               MUL(a[i], b[j], UV+1, UV[0]); 
               ADDC(0, UV[0], u, carry, v); 
               u = UV[1] + carry;
               ADDC(0, c[i+j], v, carry, v); 
               u = u + carry;
               c[i+j] = v;
          }
          c[nwords+i] = u;
     }
}


void fpmul751_mont_basic(felm_t ma, felm_t mb, felm_t mc)
{ // Basic Montgomery multiplication, mc = ma*mb*R^-1 mod p751, where ma,mb,mc in [0, p751-1] and R = 2^768.
  // ma and mb are assumed to be in Montgomery representation.
  // The Montgomery constant pp751 = -p751^(-1) mod R is the global value "Montgomery_pp751".   
    unsigned int i, bout = 0;
    digit_t mask, P[2*NWORDS_FIELD], Q[2*NWORDS_FIELD], temp[2*NWORDS_FIELD];

    mp_mul_basic(ma, mb, P, NWORDS_FIELD);                          // P = ma * mb
    mp_mul_basic(P, (digit_t*)&Montgomery_pp751, Q, NWORDS_FIELD);  // Q = P * pp751 mod R
    mp_mul_basic(Q, (digit_t*)&p751, temp, NWORDS_FIELD);           // temp = Q * p751
    mp_add(P, temp, temp, 2*NWORDS_FIELD);                    // temp = P + Q * p751     

    for (i = 0; i < NWORDS_FIELD; i++) {                      // mc = (P + Q * p751)/R
        mc[i] = temp[NWORDS_FIELD+i];
    }

    // Final, constant-time subtraction     
    bout = mp_sub(mc, (digit_t*)&p751, mc, NWORDS_FIELD);     // (bout, mc) = mc - p751
    mask = 0 - (digit_t)bout;                                 // if mc < 0 then mask = 0xFF..F, else if mc >= 0 then mask = 0x00..0

    for (i = 0; i < NWORDS_FIELD; i++) {                      // temp = mask & p751
        temp[i] = (((digit_t*)p751)[i] & mask);
    }
    mp_add(mc, temp, mc, NWORDS_FIELD);                       //  mc = mc + (mask & p751)

    return;
}


void to_mont_basic(felm_t a, felm_t mc)
{ // Conversion to Montgomery representation
  // mc = a*R^2*R^-1 mod p751 = a*R mod p751, where a in [0, p751-1]
  // The Montgomery constant R^2 mod p751 is the global value "Montgomery_R2". 

    fpmul751_mont_basic(a, (digit_t*)&Montgomery_R2, mc);
}


void from_mont_basic(felm_t ma, felm_t c)
{ // Conversion from Montgomery representation to standard representation
  // c = ma*R^-1 mod p751 = a mod p751, where ma in [0, p751-1]. 
    digit_t one[NWORDS_FIELD] = {0};
    
    one[0] = 1;
    fpmul751_mont_basic(ma, one, c);
}