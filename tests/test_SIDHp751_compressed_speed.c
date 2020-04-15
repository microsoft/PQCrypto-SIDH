/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp751_compressed_speed
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#define SCHEME_NAME    "SIDHp751_compressed_speed"
#include "../src/P751/P751_compressed_speed_api.h"



#define random_mod_order_A            random_mod_order_A_SIDHp751
#define random_mod_order_B            random_mod_order_B_SIDHp751
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp751_Compressed_Speed
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp751_Compressed_Speed
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp751_Compressed_Speed
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp751_Compressed_Speed

#include "test_sidh.c"