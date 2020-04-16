/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp751_compressed
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P751/P751_compressed_api.h"


#define SCHEME_NAME    "SIDHp751_compressed"

#define random_mod_order_A            random_mod_order_A_SIDHp751
#define random_mod_order_B            random_mod_order_B_SIDHp751
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp751_Compressed
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp751_Compressed
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp751_Compressed
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp751_Compressed

#include "test_sidh.c"