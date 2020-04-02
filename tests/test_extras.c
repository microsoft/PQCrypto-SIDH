/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: utility functions for testing and benchmarking
*********************************************************************************************/

#include "test_extras.h"
#if (OS_TARGET == OS_WIN)
    #include <intrin.h>
#endif
#if (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
    #include <time.h>
#endif
#include <stdlib.h>


static uint64_t p434[7]  = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFDC1767AE2FFFFFF, 
                             0x7BC65C783158AEA3, 0x6CFC5FD681C52056, 0x0002341F27177344 };
static uint64_t p503[8]  = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xABFFFFFFFFFFFFFF, 
                             0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E };
static uint64_t p610[10] = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x6E01FFFFFFFFFFFF, 
                             0xB1784DE8AA5AB02E, 0x9AE7BF45048FF9AB, 0xB255B2FA10C4252A, 0x819010C251E7D88C, 0x000000027BF6A768 };
static uint64_t p751[12] = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEEAFFFFFFFFFFFFF,
                             0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C };



int64_t cpucycles(void)
{ // Access system counter for benchmarking
#if (OS_TARGET == OS_WIN) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    return __rdtsc();
#elif (OS_TARGET == OS_WIN) && (TARGET == TARGET_ARM)
    return __rdpmccntr64();
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    unsigned int hi, lo;
    __asm__ volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM || TARGET == TARGET_ARM64 )
    struct timespec time;

    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)(time.tv_sec*1e9 + time.tv_nsec);
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_S390X)
    uint64_t tod;
    __asm__ volatile("stck %0\n" : "=Q" (tod) : : "cc");
    return (tod);
#else
    return 0;            
#endif
}


int compare_words(digit_t* a, digit_t* b, unsigned int nwords)
{ // Comparing "nword" elements, a=b? : (1) a>b, (0) a=b, (-1) a<b
  // SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
    int i;

    for (i = nwords-1; i >= 0; i--)
    {
        if (a[i] > b[i]) return 1;
        else if (a[i] < b[i]) return -1;
    }

    return 0; 
}


static void sub_test(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Subtraction without borrow, c = a-b where a>b
  // SECURITY NOTE: this function does not have constant-time execution. It is for TESTING ONLY.     
    unsigned int i;
    digit_t res, carry, borrow = 0;
  
    for (i = 0; i < nwords; i++)
    {
        res = a[i] - b[i];
        carry = (a[i] < b[i]);
        c[i] = res - borrow;
        borrow = carry || (res < borrow);
    } 
}


void fprandom434_test(digit_t* a)
{ // Generating a pseudo-random field element in [0, p434-1] 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.
    unsigned int i, diff = 448-434, nwords = NBITS_TO_NWORDS(434);
    unsigned char* string = NULL;

    string = (unsigned char*)a;
    for (i = 0; i < sizeof(digit_t)*nwords; i++) {
        *(string + i) = (unsigned char)rand();              // Obtain 448-bit number
    }
    a[nwords-1] &= (((digit_t)(-1) << diff) >> diff);

    while (compare_words((digit_t*)p434, a, nwords) < 1) {  // Force it to [0, modulus-1]
        sub_test(a, (digit_t*)p434, a, nwords);
    }
}


void fp2random434_test(digit_t* a)
{ // Generating a pseudo-random element in GF(p434^2) 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.

    fprandom434_test(a);
    fprandom434_test(a+NBITS_TO_NWORDS(434));
}


void fprandom503_test(digit_t* a)
{ // Generating a pseudo-random field element in [0, p503-1] 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.
    unsigned int i, diff = 512-503, nwords = NBITS_TO_NWORDS(503);
    unsigned char* string = NULL;

    string = (unsigned char*)a;
    for (i = 0; i < sizeof(digit_t)*nwords; i++) {
        *(string + i) = (unsigned char)rand();              // Obtain 512-bit number
    }
    a[nwords-1] &= (((digit_t)(-1) << diff) >> diff);

    while (compare_words((digit_t*)p503, a, nwords) < 1) {  // Force it to [0, modulus-1]
        sub_test(a, (digit_t*)p503, a, nwords);
    }
}


void fp2random503_test(digit_t* a)
{ // Generating a pseudo-random element in GF(p503^2) 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.

    fprandom503_test(a);
    fprandom503_test(a+NBITS_TO_NWORDS(503));
}


void fprandom610_test(digit_t* a)
{ // Generating a pseudo-random field element in [0, p610-1] 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.
    unsigned int i, diff = 640-610, nwords = NBITS_TO_NWORDS(610);
    unsigned char* string = NULL;

    string = (unsigned char*)a;
    for (i = 0; i < sizeof(digit_t)*nwords; i++) {
        *(string + i) = (unsigned char)rand();              // Obtain 640-bit number
    }
    a[nwords-1] &= (((digit_t)(-1) << diff) >> diff);

    while (compare_words((digit_t*)p610, a, nwords) < 1) {  // Force it to [0, modulus-1]
        sub_test(a, (digit_t*)p610, a, nwords);
    }
}


void fp2random610_test(digit_t* a)
{ // Generating a pseudo-random element in GF(p610^2) 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.

    fprandom610_test(a);
    fprandom610_test(a+NBITS_TO_NWORDS(610));
}


void fprandom751_test(digit_t* a)
{ // Generating a pseudo-random field element in [0, p751-1] 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.
    unsigned int i, diff = 768-751, nwords = NBITS_TO_NWORDS(751);
    unsigned char* string = NULL;

    string = (unsigned char*)a;
    for (i = 0; i < sizeof(digit_t)*nwords; i++) {
        *(string + i) = (unsigned char)rand();              // Obtain 768-bit number
    }
    a[nwords-1] &= (((digit_t)(-1) << diff) >> diff);

    while (compare_words((digit_t*)p751, a, nwords) < 1) {  // Force it to [0, modulus-1]
        sub_test(a, (digit_t*)p751, a, nwords);
    }
}


void fp2random751_test(digit_t* a)
{ // Generating a pseudo-random element in GF(p751^2) 
  // SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.

    fprandom751_test(a);
    fprandom751_test(a+NBITS_TO_NWORDS(751));
}
