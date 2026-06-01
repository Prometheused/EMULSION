// 
// 
/**************************************
 *          Dilithium Algorithm            *
 **************************************
 *
 *Compile:          gcc AMF.c -o AMF -loqs -lcrypto -lssl
 * 
 *Run:              ./AMF
 *
 *Documentation:    OpenSSL & Open Quantum Safe Library
 *
 * Created By:      << * >>
_______________________________________________________________________________*/


//Header Files
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ALG "Dilithium2"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
    printf("----------------------------------\n");
}

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

int main() {
    OQS_SIG *sig = OQS_SIG_new(ALG);
    size_t pk_len = sig->length_public_key;
    size_t sk_len = sig->length_secret_key;
    size_t sig_max_len = sig->length_signature;

    uint8_t pk_CKG[pk_len], sk_CKG[sk_len];
    uint8_t pk_AMF[pk_len], sk_AMF[sk_len];
    uint8_t pk_BS[pk_len], sk_BS[sk_len];

    OQS_SIG_keypair(sig, pk_CKG, sk_CKG);
    OQS_SIG_keypair(sig, pk_AMF, sk_AMF);
    OQS_SIG_keypair(sig, pk_BS, sk_BS);

    // Save and print public keys
    write_file("PK_CKG.txt", pk_CKG, pk_len);
    print_hex("PK_CKG", pk_CKG, pk_len);

    write_file("PK_AMF.txt", pk_AMF, pk_len);
    print_hex("PK_AMF", pk_AMF, pk_len);

    write_file("PK_BS.txt", pk_BS, pk_len);
    print_hex("PK_BS", pk_BS, pk_len);

    // Save and print BS secret key
    write_file("sk_BS.txt", sk_BS, sk_len);
    print_hex("sk_BS", sk_BS, sk_len);

    // Certificates
    uint8_t cert_AMF[sig_max_len]; size_t len1;
    uint8_t cert_BS[sig_max_len]; size_t len2;

    OQS_SIG_sign(sig, cert_AMF, &len1, pk_AMF, pk_len, sk_CKG);
    OQS_SIG_sign(sig, cert_BS, &len2, pk_BS, pk_len, sk_AMF);

    save_binary("Certificate_AMF.bin", cert_AMF, len1);
    print_hex("Certificate_AMF", cert_AMF, len1);

    save_binary("Certificate_BS.bin", cert_BS, len2);
    print_hex("Certificate_BS", cert_BS, len2);

    OQS_SIG_free(sig);
    printf("[AMF] Keys and certificates generated.\n");
    return 0;
}
