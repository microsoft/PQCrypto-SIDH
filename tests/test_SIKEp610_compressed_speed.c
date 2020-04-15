/**********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism SIKEp610_compressed
***********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#define SCHEME_NAME    "SIKEp610_compressed_speed"
#include "../src/P610/P610_compressed_speed.c"



#define crypto_kem_keypair            crypto_kem_keypair_SIKEp610_compressed_speed
#define crypto_kem_enc                crypto_kem_enc_SIKEp610_compressed_speed
#define crypto_kem_dec                crypto_kem_dec_SIKEp610_compressed_speed

#include "test_sike.c"
