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


void read_hex_file(const char *fname, uint8_t *buf, size_t len) {
    FILE *f = fopen(fname, "r");
    for (size_t i = 0; i < len; i++) {
        fscanf(f, "%2hhx", &buf[i]);
    }
    fclose(f);
}

void write_binary(const char *fname, const uint8_t *data, size_t len) {
    FILE *f = fopen(fname, "wb");
    fwrite(data, 1, len, f);
    fclose(f);
}

void bs(){
    int runs = 1;
    //printf("Enter number of signing runs: ");
    //scanf("%d", &runs);

    OQS_SIG *sig = OQS_SIG_new(ALG);
    size_t sk_len = sig->length_secret_key;
    size_t sig_max_len = sig->length_signature;

    uint8_t sk_BS[sk_len];
    read_hex_file("sk_BS_FALCON.txt", sk_BS, sk_len);

    uint8_t message[MSG_LEN];
    FILE *fmsg = fopen("message.txt", "rb");
    fread(message, 1, MSG_LEN, fmsg);
    fclose(fmsg);
    print_hex("Message", message, MSG_LEN);

    FILE *fsig = fopen("signature.bin", "wb");
    double total_time = 0.0;

    for (int i = 0; i < runs; i++) {
        uint8_t signature[sig_max_len];
        size_t sig_len;

        struct timespec ts1, ts2;
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        OQS_SIG_sign(sig, signature, &sig_len, message, MSG_LEN, sk_BS);
        clock_gettime(CLOCK_MONOTONIC, &ts2);

        double time_diff = (ts2.tv_sec - ts1.tv_sec) * 1e9 + (ts2.tv_nsec - ts1.tv_nsec);
        total_time += time_diff / 1e9;

        if (i == 0) fwrite(signature, 1, sig_len, fsig);
        printf("Run #%d Signature (%zu bytes):\n", i + 1, sig_len);
        print_hex("Signature", signature, sig_len);
    }

    fclose(fsig);
    OQS_SIG_free(sig);

    printf("Average Signing Time: %.9f sec\n", total_time / runs);
    return 0;
}


}
}
}