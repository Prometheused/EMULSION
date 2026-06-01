// 
// 
/**************************************
 *          Dilithium Algorithm            *
 **************************************
 *
 *Compile:          gcc UE.c -o UE -loqs -lcrypto -lssl
 * 
 *Run:              ./UE
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
#include <time.h>

#define ALG "Falcon-padded-512"
#define MSG_LEN 79

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
    printf("----------------------------------\n");
}

void read_hex_file(const char *fname, uint8_t *buf, size_t len) {
    FILE *f = fopen(fname, "r");
    for (size_t i = 0; i < len; i++) {
        fscanf(f, "%2hhx", &buf[i]);
    }
    fclose(f);
}

size_t read_binary(const char *fname, uint8_t *buf, size_t maxlen) {
    FILE *f = fopen(fname, "rb");
    size_t n = fread(buf, 1, maxlen, f);
    fclose(f);
    return n;
}

int main() {
    int runs;
    printf("Enter number of verification runs: ");
    scanf("%d", &runs);

    OQS_SIG *sig = OQS_SIG_new(ALG);
    size_t pk_len = sig->length_public_key;
    size_t sig_max_len = sig->length_signature;

    // Load public keys
    uint8_t pk_CKG[pk_len], pk_AMF[pk_len], pk_BS[pk_len];
    read_hex_file("PK_CKG.txt", pk_CKG, pk_len);
    read_hex_file("PK_AMF.txt", pk_AMF, pk_len);
    read_hex_file("PK_BS.txt", pk_BS, pk_len);

    // Load certs
    uint8_t cert_AMF[sig_max_len], cert_BS[sig_max_len];
    size_t len1 = read_binary("Certificate_AMF.bin", cert_AMF, sig_max_len);
    size_t len2 = read_binary("Certificate_BS.bin", cert_BS, sig_max_len);

    // Load message
    uint8_t message[MSG_LEN];
    FILE *fmsg = fopen("message.txt", "rb");
    fread(message, 1, MSG_LEN, fmsg);
    fclose(fmsg);
    print_hex("Message", message, MSG_LEN);

    // Load message signature
    uint8_t signature[sig_max_len];
    size_t sig_len = read_binary("signature.bin", signature, sig_max_len);

    double total_time = 0.0;
    double total_time_sig = 0.0;

    for (int i = 0; i < runs; i++) {
        struct timespec ts1, ts2;
        struct timespec ts1sig, ts2sig;
        clock_gettime(CLOCK_MONOTONIC, &ts1);

        int cert1 = OQS_SIG_verify(sig, pk_AMF, pk_len, cert_AMF, len1, pk_CKG);
        int cert2 = OQS_SIG_verify(sig, pk_BS, pk_len, cert_BS, len2, pk_AMF);
        clock_gettime(CLOCK_MONOTONIC, &ts1sig);
        int sig_ok = OQS_SIG_verify(sig, message, MSG_LEN, signature, sig_len, pk_BS);
        clock_gettime(CLOCK_MONOTONIC, &ts2sig);

        clock_gettime(CLOCK_MONOTONIC, &ts2);
        double dt = (ts2.tv_sec - ts1.tv_sec) * 1e9 + (ts2.tv_nsec - ts1.tv_nsec);
        double dtsig = (ts2sig.tv_sec - ts1sig.tv_sec) * 1e9 + (ts2sig.tv_nsec - ts1sig.tv_nsec);
        total_time += dt / 1e9;
        total_time_sig += dtsig / 1e9;

        printf("Run #%d - Cert1: %s, Cert2: %s, Signature: %s\n", i + 1,
               cert1 == OQS_SUCCESS ? "✅" : "❌",
               cert2 == OQS_SUCCESS ? "✅" : "❌",
               sig_ok == OQS_SUCCESS ? "✅" : "❌");
    }

    OQS_SIG_free(sig);
    printf("Average Verification Time: %.9f sec\n", total_time / runs);
    printf("Average One Signature Verification Time: %.9f sec\n", total_time_sig / runs);
    return 0;
}
