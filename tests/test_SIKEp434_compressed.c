/**********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism SIKEp434_compressed
***********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P434/P434_compressed.c"


#define SCHEME_NAME    "SIKEp434_compressed"

#define crypto_kem_keypair            crypto_kem_keypair_SIKEp434_compressed
#define crypto_kem_enc                crypto_kem_enc_SIKEp434_compressed
#define crypto_kem_dec                crypto_kem_dec_SIKEp434_compressed

#include "test_sike.c"
