/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp434_compressed
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P434/P434_compressed_speed_api.h"


#define SCHEME_NAME    "SIDHp434_compressed_speed"


#define random_mod_order_A            random_mod_order_A_SIDHp434
#define random_mod_order_B            random_mod_order_B_SIDHp434
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp434_Compressed_Speed
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp434_Compressed_Speed
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp434_Compressed_Speed
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp434_Compressed_Speed

#define crypto_kem_keypair    crypto_kem_keypair_SIKEp434_compressed_speed
#define crypto_kem_enc        crypto_kem_enc_SIKEp434_compressed_speed
#define crypto_kem_dec        crypto_kem_dec_SIKEp434_compressed_speed

#include "test_sidh.c"