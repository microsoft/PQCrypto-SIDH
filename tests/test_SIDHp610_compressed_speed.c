/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp610_compressed_speed
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#define SCHEME_NAME    "SIDHp610_compressed_speed"
#include "../src/P610/P610_compressed_speed_api.h"



#define random_mod_order_A            random_mod_order_A_SIDHp610
#define random_mod_order_B            random_mod_order_B_SIDHp610
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp610_Compressed_Speed
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp610_Compressed_Speed
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp610_Compressed_Speed
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp610_Compressed_Speed

#include "test_sidh.c"