/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: utility header file for tests
*********************************************************************************************/  

#ifndef __TEST_EXTRAS_H__
#define __TEST_EXTRAS_H__
    
#include "../src/config.h"

#define PASSED    0
#define FAILED    1


#if (TARGET == TARGET_ARM || TARGET == TARGET_ARM64)
    #define print_unit printf("nsec");
#else
    #define print_unit printf("cycles");
#endif

    
// Access system counter for benchmarking
int64_t cpucycles(void);

// Comparing "nword" elements, a=b? : (1) a!=b, (0) a=b
int compare_words(digit_t* a, digit_t* b, unsigned int nwords);

// Generating a pseudo-random field element in [0, p503-1] 
void fprandom503_test(digit_t* a);

// Generating a pseudo-random element in GF(p503^2)
void fp2random503_test(digit_t* a);

// Generating a pseudo-random field element in [0, p751-1] 
void fprandom751_test(digit_t* a);

// Generating a pseudo-random element in GF(p751^2)
void fp2random751_test(digit_t* a);


#endif