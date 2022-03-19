/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
* Copyright (c) Microsoft Corporation
*
* Website: https://github.com/microsoft/PQCrypto-SIDH
* Released under MIT license
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp751
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P751/P751_api.h"


#define SCHEME_NAME    "SIDHp751"

#define random_mod_order_A            random_mod_order_A_SIDHp751
#define random_mod_order_B            random_mod_order_B_SIDHp751
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp751
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp751
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp751
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp751

#include "test_sidh.c"