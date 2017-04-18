/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: API header file
*
*********************************************************************************************/  

#ifndef __SIDH_API_H__
#define __SIDH_API_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include "SIDH.h"


/*********************** Ephemeral key exchange API ***********************/ 

// SECURITY NOTE: SIDH supports ephemeral Diffie-Hellman key exchange. It is NOT secure to use it with static keys.
// See "On the Security of Supersingular Isogeny Cryptosystems", S.D. Galbraith, C. Petit, B. Shani and Y.B. Ti, in ASIACRYPT 2016, 2016.
// Extended version available at: http://eprint.iacr.org/2016/859   

// Alice's ephemeral key-pair generation
// It produces a private key pPrivateKeyA and computes the public key pPublicKeyA.
// The private key is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).  
// The public key consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
CRYPTO_STATUS EphemeralKeyGeneration_A(unsigned char* pPrivateKeyA, unsigned char* pPublicKeyA, PCurveIsogenyStruct CurveIsogeny);

// Bob's ephemeral key-pair generation
// It produces a private key pPrivateKeyB and computes the public key pPublicKeyB.
// The private key is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).  
// The public key consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
CRYPTO_STATUS EphemeralKeyGeneration_B(unsigned char* pPrivateKeyB, unsigned char* pPublicKeyB, PCurveIsogenyStruct CurveIsogeny);

// Alice's ephemeral shared secret computation
// It produces a shared secret key pSharedSecretA using her secret key pPrivateKeyA and Bob's public key pPublicKeyB
// Inputs: Alice's pPrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total). 
//         Bob's pPublicKeyB consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// Output: a shared secret pSharedSecretA that consists of one element in GF(p751^2), i.e., 1502 bits in total. 
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
CRYPTO_STATUS EphemeralSecretAgreement_A(const unsigned char* pPrivateKeyA, const unsigned char* pPublicKeyB, unsigned char* pSharedSecretA, PCurveIsogenyStruct CurveIsogeny);

// Bob's ephemeral shared secret computation
// It produces a shared secret key pSharedSecretB using his secret key pPrivateKeyB and Alice's public key pPublicKeyA
// Inputs: Bob's pPrivateKeyB is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total). 
//         Alice's pPublicKeyA consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// Output: a shared secret pSharedSecretB that consists of one element in GF(p751^2), i.e., 1502 bits in total. 
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
CRYPTO_STATUS EphemeralSecretAgreement_B(const unsigned char* pPrivateKeyB, const unsigned char* pPublicKeyA, unsigned char* pSharedSecretB, PCurveIsogenyStruct CurveIsogeny);

/*********************** Ephemeral key exchange API with compressed public keys ***********************/

// Alice's public key compression
// It produces a compressed output that consists of three elements in Z_orderB and one field element
// Input : Alice's public key PublicKeyA, which consists of 3 elements in GF(p751^2).
// Output: a compressed value CompressedPKA that consists of three elements in Z_orderB and one element in GF(p751^2). 
// CurveIsogeny must be set up in advance using SIDH_curve_initialize(). 
void PublicKeyCompression_A(const unsigned char* PublicKeyA, unsigned char* CompressedPKA, PCurveIsogenyStruct CurveIsogeny);

// Alice's public key value decompression computed by Bob
// Inputs: Bob's private key SecretKeyB, and
//         Alice's compressed public key data CompressedPKA, which consists of three elements in Z_orderB and one element in GF(p751^2),
// Output: a point point_R in coordinates (X:Z) and the curve parameter param_A in GF(p751^2). Outputs are stored in Montgomery representation.
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().                                                                    
void PublicKeyADecompression_B(const unsigned char* SecretKeyB, const unsigned char* CompressedPKA, unsigned char* point_R, unsigned char* param_A, PCurveIsogenyStruct CurveIsogeny);

// Alice's ephemeral shared secret computation
// It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
// Inputs: Alice's PrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total). 
//         Bob's PublicKeyB consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// Output: a shared secret SharedSecretA that consists of one element in GF(p751^2), i.e., 1502 bits in total. 
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
CRYPTO_STATUS EphemeralSecretAgreement_Compression_A(const unsigned char* PrivateKeyA, const unsigned char* point_R, const unsigned char* param_A, unsigned char* SharedSecretA, PCurveIsogenyStruct CurveIsogeny);

// Bob's public key compression
// It produces a compressed output that consists of three elements in Z_orderA and one field element
// Input : Bob's public key PublicKeyB, which consists of 3 elements in GF(p751^2).
// Output: a compressed value CompressedPKB that consists of three elements in Z_orderA and one element in GF(p751^2). 
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().       
void PublicKeyCompression_B(const unsigned char* PublicKeyB, unsigned char* CompressedPKB, PCurveIsogenyStruct CurveIsogeny);

// Bob's public key value decompression computed by Alice
// Inputs: Alice's private key SecretKeyA, and
//         Bob's compressed public key data CompressedPKB, which consists of three elements in Z_orderA and one element in GF(p751^2).
// Output: a point point_R in coordinates (X:Z) and the curve parameter param_A in GF(p751^2). Outputs are stored in Montgomery representation.
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().            
void PublicKeyBDecompression_A(const unsigned char* SecretKeyA, const unsigned char* CompressedPKB, unsigned char* point_R, unsigned char* param_A, PCurveIsogenyStruct CurveIsogeny);

// Bob's ephemeral shared secret computation
// It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's decompressed data point_R and param_A
// Inputs: Bob's PrivateKeyB is an integer in the range [1, oB-1], where oB = 3^239. 
//         Alice's decompressed data consists of point_R in (X:Z) coordinates and the curve paramater param_A in GF(p751^2).
// Output: a shared secret SharedSecretB that consists of one element in GF(p751^2). 
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().                       
CRYPTO_STATUS EphemeralSecretAgreement_Compression_B(const unsigned char* PrivateKeyB, const unsigned char* point_R, const unsigned char* param_A, unsigned char* SharedSecretB, PCurveIsogenyStruct CurveIsogeny);

/*********************** Scalar multiplication API using BigMont ***********************/ 

// BigMont's scalar multiplication using the Montgomery ladder
// Inputs: x, the affine x-coordinate of a point P on BigMont: y^2=x^3+A*x^2+x, 
//         scalar m.
// Output: xout, the affine x-coordinate of m*(x:1)
// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
CRYPTO_STATUS BigMont_ladder(unsigned char* x, digit_t* m, unsigned char* xout, PCurveIsogenyStruct CurveIsogeny);


// Encoding of keys for isogeny system "SIDHp751" (wire format):
// ------------------------------------------------------------
// Elements over GF(p751) are encoded in 96 octets in little endian format (i.e., the least significant octet located at the leftmost position). 
// Elements (a+b*i) over GF(p751^2), where a and b are defined over GF(p751), are encoded as {b, a}, with b in the least significant position.
// Elements over Z_oA and Z_oB are encoded in 48 octets in little endian format. 
//
// Private keys pPrivateKeyA and pPrivateKeyB are defined in Z_oA and Z_oB (resp.) and can have values in the range [2, 2^372-2] and [1, 3^239-1], resp.
// In the key exchange API, they are encoded in 48 octets in little endian format. 
// Public keys pPublicKeyA and pPublicKeyB consist of four elements in GF(p751^2). In the key exchange API, they are encoded in 768 octets in little
// endian format. 
// Shared keys pSharedSecretA and pSharedSecretB consist of one element in GF(p751^2). In the key exchange API, they are encoded in 192 octets in little
// endian format. 


#ifdef __cplusplus
}
#endif


#endif
