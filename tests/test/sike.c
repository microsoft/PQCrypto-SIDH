/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: isogeny-based key encapsulation mechanism (KEM)
*
*********************************************************************************************/ 

#include <string.h>
#include "sha3/fips202.h"


int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{ // SIKE's key generation
  // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = CRYPTO_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          public key pk (CRYPTO_PUBLICKEYBYTES bytes) 

    // Generate lower portion of secret key sk <- s||SK
    RandomBytesFunction(sk, CRYPTO_BYTES);
    random_mod_order_B(sk + CRYPTO_BYTES);

    // Generate public key pk
    EphemeralKeyGeneration_B(sk + CRYPTO_BYTES, pk);

    // Append public key pk to secret key sk
    memcpy(&sk[CRYPTO_BYTES + SECRETKEY_B_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

    return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // SIKE's encapsulation
  // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
  // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
  //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES bytes) 
    const uint16_t G = 0;
    const uint16_t H = 1;
    const uint16_t P = 2;
    unsigned char ephemeralsk[SECRETKEY_A_BYTES];
    unsigned char jinvariant[FP2_ENCODED_BYTES];
    unsigned char h[CRYPTO_BYTES];
    unsigned char message[CRYPTO_BYTES];
    unsigned char temp[SHAKE256_RATE+CRYPTO_CIPHERTEXTBYTES+3];
    unsigned int i;

    // Generate ephemeralsk <- KMAC() mod oA 
    RandomBytesFunction(message, CRYPTO_BYTES);
    kmac256_simple(ephemeralsk, SECRETKEY_A_BYTES, G, pk, (unsigned long long)CRYPTO_PUBLICKEYBYTES, message, CRYPTO_BYTES, temp);
    ephemeralsk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Encrypt
    EphemeralKeyGeneration_A(ephemeralsk, ct);
    EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);
    cshake256_simple(h, CRYPTO_BYTES, P, jinvariant, FP2_ENCODED_BYTES); // TODO: PRF
    for (i = 0; i < CRYPTO_BYTES; i++) ct[i + CRYPTO_PUBLICKEYBYTES] = message[i] ^ h[i];

    // Generate shared secret ss <- KMAC()
    kmac256_simple(ss, CRYPTO_BYTES, H, ct, (unsigned long long)CRYPTO_CIPHERTEXTBYTES, message, CRYPTO_BYTES, temp);

    return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // SIKE's decapsulation
  // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = CRYPTO_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
  //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES bytes) 
  // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    const uint16_t G = 0;
    const uint16_t H = 1;
    const uint16_t P = 2;
    unsigned char ephemeralsk_[SECRETKEY_A_BYTES];
    unsigned char jinvariant_[FP2_ENCODED_BYTES];
    unsigned char h_[CRYPTO_BYTES];
    unsigned char message_[CRYPTO_BYTES];
    unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char temp[SHAKE256_RATE+CRYPTO_CIPHERTEXTBYTES+3];
    unsigned int i;

    // Decrypt
    EphemeralSecretAgreement_B(sk + CRYPTO_BYTES, ct, jinvariant_);
    cshake256_simple(h_, CRYPTO_BYTES, P, jinvariant_, FP2_ENCODED_BYTES); // TODO: PRF
    for (i = 0; i < CRYPTO_BYTES; i++) message_[i] = ct[i + CRYPTO_PUBLICKEYBYTES] ^ h_[i];

    // Generate ephemeralsk_ <- KMAC() mod oA
    memcpy(pk, &sk[CRYPTO_BYTES + SECRETKEY_B_BYTES], CRYPTO_PUBLICKEYBYTES);
    kmac256_simple(ephemeralsk_, SECRETKEY_A_BYTES, G, pk, (unsigned long long)CRYPTO_PUBLICKEYBYTES, message_, CRYPTO_BYTES, temp);
    ephemeralsk_[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    EphemeralKeyGeneration_A(ephemeralsk_, c0_);
    if (memcmp(c0_, ct, CRYPTO_PUBLICKEYBYTES) == 0) {
        kmac256_simple(ss, CRYPTO_BYTES, H, ct, (unsigned long long)CRYPTO_CIPHERTEXTBYTES, message_, CRYPTO_BYTES, temp);
    } else {
        kmac256_simple(ss, CRYPTO_BYTES, H, ct, (unsigned long long)CRYPTO_CIPHERTEXTBYTES, sk, CRYPTO_BYTES, temp);
    }

    return 0;
}