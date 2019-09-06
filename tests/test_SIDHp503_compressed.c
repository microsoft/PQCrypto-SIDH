/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp503_compressed
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P503/P503_compressed_api.h"


#define SCHEME_NAME    "SIDHp503_compressed"

#define random_mod_order_A            random_mod_order_A_SIDHp503
#define random_mod_order_B            random_mod_order_B_SIDHp503
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp503_Compressed
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp503_Compressed
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp503_Compressed
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp503_Compressed

#include "test_sidh.c"