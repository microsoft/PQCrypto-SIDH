/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
* Copyright (c) Microsoft Corporation
*
* Website: https://github.com/microsoft/PQCrypto-SIDH
* Released under MIT license
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp434
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P434/P434_api.h"


#define SCHEME_NAME    "SIDHp434"

#define random_mod_order_A            random_mod_order_A_SIDHp434
#define random_mod_order_B            random_mod_order_B_SIDHp434
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp434
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp434
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp434
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp434

#include "test_sidh.c"