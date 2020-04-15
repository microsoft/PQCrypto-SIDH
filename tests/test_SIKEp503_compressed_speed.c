/**********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism SIKEp503_compressed_speed
***********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#define SCHEME_NAME    "SIKEp503_compressed_speed"
#include "../src/P503/P503_compressed_speed.c"



#define crypto_kem_keypair            crypto_kem_keypair_SIKEp503_compressed_speed
#define crypto_kem_enc                crypto_kem_enc_SIKEp503_compressed_speed
#define crypto_kem_dec                crypto_kem_dec_SIKEp503_compressed_speed

#include "test_sike.c"
