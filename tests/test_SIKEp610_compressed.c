/**********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism SIKEp610_compressed
***********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P610/P610_compressed.c"


#define SCHEME_NAME    "SIKEp610_compressed"

#define crypto_kem_keypair            crypto_kem_keypair_SIKEp610_compressed
#define crypto_kem_enc                crypto_kem_enc_SIKEp610_compressed
#define crypto_kem_dec                crypto_kem_dec_SIKEp610_compressed

#include "test_sike.c"
