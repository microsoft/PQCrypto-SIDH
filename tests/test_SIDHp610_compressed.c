/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp610_compressed
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P610/P610_compressed_api.h"


#define SCHEME_NAME    "SIDHp610_compressed"

#define random_mod_order_A            random_mod_order_A_SIDHp610
#define random_mod_order_B            random_mod_order_B_SIDHp610
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp610_Compressed
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp610_Compressed
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp610_Compressed
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp610_Compressed

#include "test_sidh.c"