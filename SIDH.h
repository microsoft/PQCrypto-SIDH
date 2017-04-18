/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: main header file
*
*********************************************************************************************/  

#ifndef __SIDH_H__
#define __SIDH_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


// Definition of operating system

#define OS_WIN       1
#define OS_LINUX     2

#if defined(__WINDOWS__)        // Microsoft Windows OS
    #define OS_TARGET OS_WIN
#elif defined(__LINUX__)        // Linux OS
    #define OS_TARGET OS_LINUX 
#else
    #error -- "Unsupported OS"
#endif


// Definition of compiler

#define COMPILER_VC      1
#define COMPILER_GCC     2
#define COMPILER_CLANG   3

#if defined(_MSC_VER)           // Microsoft Visual C compiler
    #define COMPILER COMPILER_VC
#elif defined(__GNUC__)         // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#elif defined(__clang__)        // Clang compiler
    #define COMPILER COMPILER_CLANG
#else
    #error -- "Unsupported COMPILER"
#endif


// Definition of the targeted architecture and basic data types
    
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_ARM          3
#define TARGET_ARM64        4

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64
    #define RADIX           64
    typedef uint64_t        digit_t;        // Unsigned 64-bit digit
    typedef int64_t         sdigit_t;       // Signed 64-bit digit
    typedef uint32_t        hdigit_t;       // Unsigned 32-bit digit
    #define NWORDS_FIELD    12              // Number of words of a 751-bit field element
    #define p751_ZERO_WORDS 5               // Number of "0" digits in the least significant part of p751 + 1     
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX           32
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
    typedef uint16_t        hdigit_t;       // Unsigned 16-bit digit
    #define NWORDS_FIELD    24 
    #define p751_ZERO_WORDS 11
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX           32
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
    typedef uint16_t        hdigit_t;       // Unsigned 16-bit digit
    #define NWORDS_FIELD    24
    #define p751_ZERO_WORDS 11
#elif defined(_ARM64_)
    #define TARGET TARGET_ARM64
    #define RADIX           64
    typedef uint64_t        digit_t;
    typedef int64_t         sdigit_t;
    typedef uint32_t        hdigit_t;
    #define NWORDS_FIELD    12
    #define p751_ZERO_WORDS 5
#else
    #error -- "Unsupported ARCHITECTURE"
#endif

#define RADIX64         64


// Selection of generic, portable implementation

#if defined(_GENERIC_)                      
    #define GENERIC_IMPLEMENTATION
#endif


// Unsupported configurations

#if (TARGET != TARGET_AMD64) && (TARGET != TARGET_ARM64) && !defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif


// Extended datatype support
 
#if defined(GENERIC_IMPLEMENTATION)                       
    typedef uint64_t uint128_t[2];
#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX) && (COMPILER == COMPILER_GCC || COMPILER == COMPILER_CLANG)
    #define UINT128_SUPPORT
    typedef unsigned uint128_t __attribute__((mode(TI)));
#elif (TARGET == TARGET_ARM64 && OS_TARGET == OS_LINUX) && (COMPILER == COMPILER_GCC || COMPILER == COMPILER_CLANG)
    #define UINT128_SUPPORT
    typedef unsigned uint128_t __attribute__((mode(TI)));
#elif (TARGET == TARGET_AMD64) && (OS_TARGET == OS_WIN && COMPILER == COMPILER_VC)
    #define SCALAR_INTRIN_SUPPORT   
    typedef uint64_t uint128_t[2];
#else
    #error -- "Unsupported configuration"
#endif
    

// Basic constants

#define NBITS_FIELD     751  
#define MAXBITS_FIELD   768                
#define MAXWORDS_FIELD  ((MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD  ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 751-bit field element 
#define NBITS_ORDER     384
#define NWORDS_ORDER    ((NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER  ((NBITS_ORDER+63)/64)               // Number of 64-bit words of a 384-bit element 
#define MAXBITS_ORDER   NBITS_ORDER                         
#define MAXWORDS_ORDER  ((MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, oA-1] or [1, oB].
  
// Basic constants for elliptic curve BigMont

#define BIGMONT_NBITS_ORDER     749 
#define BIGMONT_MAXBITS_ORDER   768  
#define BIGMONT_NWORDS_ORDER    ((BIGMONT_NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of BigMont's subgroup order.
#define BIGMONT_MAXWORDS_ORDER  ((BIGMONT_MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, BigMont_order].
   

// Definitions of the error-handling type and error codes

typedef enum {
    CRYPTO_SUCCESS,                          // 0x00
    CRYPTO_ERROR,                            // 0x01
    CRYPTO_ERROR_DURING_TEST,                // 0x02
    CRYPTO_ERROR_UNKNOWN,                    // 0x03
    CRYPTO_ERROR_NOT_IMPLEMENTED,            // 0x04
    CRYPTO_ERROR_NO_MEMORY,                  // 0x05
    CRYPTO_ERROR_INVALID_PARAMETER,          // 0x06
    CRYPTO_ERROR_SHARED_KEY,                 // 0x07
    CRYPTO_ERROR_PUBLIC_KEY_VALIDATION,      // 0x08
    CRYPTO_ERROR_TOO_MANY_ITERATIONS,        // 0x09
    CRYPTO_ERROR_END_OF_LIST
} CRYPTO_STATUS;

#define CRYPTO_STATUS_TYPE_SIZE (CRYPTO_ERROR_END_OF_LIST)


// Definitions of the error messages
// NOTE: they must match the error codes above

#define CRYPTO_MSG_SUCCESS                                "CRYPTO_SUCCESS"
#define CRYPTO_MSG_ERROR                                  "CRYPTO_ERROR"
#define CRYPTO_MSG_ERROR_DURING_TEST                      "CRYPTO_ERROR_DURING_TEST"
#define CRYPTO_MSG_ERROR_UNKNOWN                          "CRYPTO_ERROR_UNKNOWN"
#define CRYPTO_MSG_ERROR_NOT_IMPLEMENTED                  "CRYPTO_ERROR_NOT_IMPLEMENTED"
#define CRYPTO_MSG_ERROR_NO_MEMORY                        "CRYPTO_ERROR_NO_MEMORY"
#define CRYPTO_MSG_ERROR_INVALID_PARAMETER                "CRYPTO_ERROR_INVALID_PARAMETER"
#define CRYPTO_MSG_ERROR_SHARED_KEY                       "CRYPTO_ERROR_SHARED_KEY"
#define CRYPTO_MSG_ERROR_PUBLIC_KEY_VALIDATION            "CRYPTO_ERROR_PUBLIC_KEY_VALIDATION"
#define CRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS              "CRYPTO_ERROR_TOO_MANY_ITERATIONS"                                                    


// Definition of type random_bytes to implement callback functions outputting "nbytes" random values to "random_array"
typedef CRYPTO_STATUS (*RandomBytes)(unsigned int nbytes, unsigned char* random_array);


// Definition of type for curve isogeny system identifiers. Currently valid value is "SIDHp751" (see SIDH.h)
typedef char CurveIsogeny_ID[10];


// Supersingular elliptic curve isogeny structures:

// This data struct contains the static curve isogeny data
typedef struct
{    
    CurveIsogeny_ID  CurveIsogeny;                           // Curve isogeny system identifier, base curve defined over GF(p^2) 
    unsigned int     pwordbits;                              // Smallest multiple of 32 larger than the prime bitlength
    unsigned int     owordbits;                              // Smallest multiple of 32 larger than the order bitlength
    unsigned int     pbits;                                  // Bitlength of the prime p
    uint64_t         prime[MAXWORDS_FIELD];                  // Prime p
    uint64_t         A[MAXWORDS_FIELD];                      // Base curve parameter "A"
    uint64_t         C[MAXWORDS_FIELD];                      // Base curve parameter "C"
    unsigned int     oAbits;                                 // Order bitlength for Alice 
    uint64_t         Aorder[MAXWORDS_ORDER];                 // Order of Alice's (sub)group 
    unsigned int     oBbits;                                 // Order bitlength for Bob 
    unsigned int     eB;                                     // Power of Bob's subgroup order (i.e., oB = 3^eB) 
    uint64_t         Border[MAXWORDS_ORDER];                 // Order of Bob's (sub)group 
    uint64_t         PA[2*MAXWORDS_FIELD];                   // Alice's generator PA = (XPA,YPA), where XPA and YPA are defined over GF(p)
    uint64_t         PB[2*MAXWORDS_FIELD];                   // Bob's generator PB = (XPB,YPB), where XPB and YPB are defined over GF(p)
    unsigned int     BigMont_A24;                            // BigMont's curve parameter A24 = (A+2)/4
    uint64_t         BigMont_order[BIGMONT_MAXWORDS_ORDER];  // BigMont's subgroup order 
    uint64_t         Montgomery_R2[MAXWORDS_FIELD];          // Montgomery constant (2^W)^2 mod p, using a suitable value W
    uint64_t         Montgomery_pp[MAXWORDS_FIELD];          // Montgomery constant -p^-1 mod 2^W, using a suitable value W
    uint64_t         Montgomery_one[MAXWORDS_FIELD];         // Value one in Montgomery representation
} CurveIsogenyStaticData, *PCurveIsogenyStaticData;


// This data struct is initialized with the targeted curve isogeny system during setup
typedef struct
{
    CurveIsogeny_ID  CurveIsogeny;                           // Curve isogeny system identifier, base curve defined over GF(p^2) 
    unsigned int     pwordbits;                              // Closest multiple of 32 to prime bitlength
    unsigned int     owordbits;                              // Closest multiple of 32 to order bitlength
    unsigned int     pbits;                                  // Bitlength of the prime p
    digit_t*         prime;                                  // Prime p
    digit_t*         A;                                      // Base curve parameter "A"
    digit_t*         C;                                      // Base curve parameter "C"
    unsigned int     oAbits;                                 // Order bitlength for Alice 
    digit_t*         Aorder;                                 // Order of Alice's (sub)group 
    unsigned int     oBbits;                                 // Order bitlength for Bob 
    unsigned int     eB;                                     // Power of Bob's subgroup order (i.e., oB = 3^eB) 
    digit_t*         Border;                                 // Order of Bob's (sub)group 
    digit_t*         PA;                                     // Alice's generator PA = (XPA,YPA), where XPA and YPA are defined over GF(p)
    digit_t*         PB;                                     // Bob's generator PB = (XPB,YPB), where XPB and YPB are defined over GF(p)
    unsigned int     BigMont_A24;                            // BigMont's curve parameter A24 = (A+2)/4
    digit_t*         BigMont_order;                          // BigMont's subgroup order
    digit_t*         Montgomery_R2;                          // Montgomery constant (2^W)^2 mod p, using a suitable value W
    digit_t*         Montgomery_pp;                          // Montgomery constant -p^-1 mod 2^W, using a suitable value W
    digit_t*         Montgomery_one;                         // Value one in Montgomery representation
    RandomBytes      RandomBytesFunction;                    // Function providing random bytes to generate nonces or secret keys
} CurveIsogenyStruct, *PCurveIsogenyStruct;


// Supported curve isogeny systems:

// "SIDHp751", base curve: supersingular elliptic curve E: y^2 = x^3 + x
extern CurveIsogenyStaticData CurveIsogeny_SIDHp751;


/******************** Function prototypes ***********************/
/*************** Setup/initialization functions *****************/ 

// Dynamic allocation of memory for curve isogeny structure.
// Returns NULL on error.
PCurveIsogenyStruct SIDH_curve_allocate(PCurveIsogenyStaticData CurveData);

// Initialize curve isogeny structure pCurveIsogeny with static data extracted from pCurveIsogenyData. 
// This needs to be called after allocating memory for "pCurveIsogeny" using SIDH_curve_allocate().
CRYPTO_STATUS SIDH_curve_initialize(PCurveIsogenyStruct pCurveIsogeny, RandomBytes RandomBytesFunction, PCurveIsogenyStaticData pCurveIsogenyData); 

// Free memory for curve isogeny structure
void SIDH_curve_free(PCurveIsogenyStruct pCurveIsogeny);

// Output error/success message for a given CRYPTO_STATUS
const char* SIDH_get_error_message(CRYPTO_STATUS Status);

// Output random values in the range [1, order-1] in little endian format that can be used as private keys.
CRYPTO_STATUS random_mod_order(digit_t* random_digits, unsigned int AliceOrBob, PCurveIsogenyStruct pCurveIsogeny);

// Output random values in the range [1, BigMont_order-1] in little endian format that can be used as private keys
// to compute scalar multiplications using the elliptic curve BigMont.
CRYPTO_STATUS random_BigMont_mod_order(digit_t* random_digits, PCurveIsogenyStruct pCurveIsogeny);

// Clear "nwords" digits from memory
void clear_words(void* mem, digit_t nwords);


#ifdef __cplusplus
}
#endif


#endif
