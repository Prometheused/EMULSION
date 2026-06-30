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


void write_file(const char *fname, const uint8_t *data, size_t len) {
    FILE *f = fopen(fname, "w");
    for (size_t i = 0; i < len; i++) fprintf(f, "%02X", data[i]);
    fprintf(f, "\n");
    fclose(f);
}

void save_binary(const char *fname, const uint8_t *data, size_t len) {
    FILE *f = fopen(fname, "wb");
    fwrite(data, 1, len, f);
    fclose(f);
}

void amf(){
    OQS_SIG *sig_cert = OQS_SIG_new(ALG_CERT); // MAYO-*
    OQS_SIG *sig_msg  = OQS_SIG_new(ALG_MSG);  // Falcon-512
    size_t pk_len_cert = sig_cert->length_public_key;
    size_t sk_len_cert = sig_cert->length_secret_key;
    size_t sig_max_len_cert = sig_cert->length_signature;
    
    size_t pk_len_msg = sig_msg->length_public_key;
    size_t sk_len_msg = sig_msg->length_secret_key;
    size_t sig_max_len_msg = sig_msg->length_signature;

    uint8_t pk_CKG[pk_len_cert], sk_CKG[sk_len_cert];
    uint8_t pk_AMF[pk_len_cert], sk_AMF[sk_len_cert];
    
    
    uint8_t pk_BS[pk_len_msg], sk_BS[sk_len_msg];

    OQS_SIG_keypair(sig_cert, pk_CKG, sk_CKG);
    OQS_SIG_keypair(sig_cert, pk_AMF, sk_AMF);
    OQS_SIG_keypair(sig_msg, pk_BS, sk_BS);

    // Save and print public keys
    write_file("PK_CKG_MAYO.txt", pk_CKG, pk_len_cert);
    print_hex("PK_CKG_MAYO", pk_CKG, pk_len_cert);

    write_file("PK_AMF_MAYO.txt", pk_AMF, pk_len_cert);
    print_hex("PK_AMF_MAYO", pk_AMF, pk_len_cert);

    write_file("PK_BS_FALCON.txt", pk_BS, pk_len_msg);
    print_hex("PK_BS_FALCON", pk_BS, pk_len_msg);

    // Save and print BS secret key
    write_file("sk_BS_FALCON.txt", sk_BS, sk_len_msg);
    print_hex("sk_BS_FALCON", sk_BS, sk_len_msg);

    // Certificates
    uint8_t cert_AMF[sig_max_len_cert]; size_t len1;
    uint8_t cert_BS[sig_max_len_cert]; size_t len2;

    OQS_SIG_sign(sig_cert, cert_AMF, &len1, pk_AMF, pk_len_cert, sk_CKG);
    OQS_SIG_sign(sig_cert, cert_BS, &len2, pk_BS, pk_len_msg, sk_AMF);

    save_binary("Certificate_AMF_MAYO.bin", cert_AMF, len1);
    print_hex("Certificate_AMF_MAYO", cert_AMF, len1);

    save_binary("Certificate_BS_MAYO.bin", cert_BS, len2);
    print_hex("Certificate_BS_MAYO", cert_BS, len2);

    OQS_SIG_free(sig_cert);
    OQS_SIG_free(sig_msg);
    printf("[AMF] Keys and certificates generated.\n");
    return 0;
}


}
}
}