/*******************************************************************
 *          Dilithium with 2-level Certificate Algorithm            *
 *******************************************************************
 *
 *Description:      1. Generate key pairs for 3 entities: Global CA, CKG, BS
 *                  2. Create the certificates by signing the public keys
 *                  3. BS signs a random message
 *                  4. UE verifies the message and the chain of certificates
 *                  5. Write all the outputs in Printed_Outup.txt file
 *                  6. All steps have timings
 *
 *  
 *Compile:          gcc Dilithium.c -o Dilithium -loqs -lcrypto
 *
 *Run:              ./Dilithium
 *
 *Documentation:    Open Quantum Safe Library + OpenSSL Library
 *
 *Created By:       << 8690bc 5dcd9c >>
_______________________________________________________________________________*/


// Headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>
#include "srsran/asn1/rrc_nr/crypto_utils.h"








namespace asn1 {
namespace rrc_nr {
namespace falcon {

inline const char* SIGNATURE_ALG = "Falcon-512";

/*************************************************************
				    F u n c t i o n s
**************************************************************/


void read_hex_file(const char *fname, uint8_t *buf, size_t len);

void write_binary(const char *fname, const uint8_t *data, size_t len);

void bs();


}
}
}