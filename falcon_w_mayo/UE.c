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

#define ALG_MSG "Falcon-padded-512"
#define ALG_CERT "MAYO-2"
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

void ue(){
    int runs;
    printf("Enter number of verification runs: ");
    scanf("%d", &runs);

    OQS_SIG *sig_cert = OQS_SIG_new(ALG_CERT); // MAYO-*
    OQS_SIG *sig_msg  = OQS_SIG_new(ALG_MSG);  // Falcon-512
    size_t pk_len_cert = sig_cert->length_public_key;
    size_t pk_len_msg = sig_msg->length_public_key;
    size_t sig_max_len_cert = sig_cert->length_signature;
    size_t sig_max_len_msg = sig_msg->length_signature;

    // Load public keys
    uint8_t pk_CKG[pk_len_cert], pk_AMF[pk_len_cert], pk_BS[pk_len_msg];
    read_hex_file("PK_CKG_MAYO.txt", pk_CKG, pk_len_cert);
    read_hex_file("PK_AMF_MAYO.txt", pk_AMF, pk_len_cert);
    read_hex_file("PK_BS_FALCON.txt", pk_BS, pk_len_msg);

    // Load certs
    uint8_t cert_AMF[sig_max_len_cert], cert_BS[sig_max_len_cert];
    size_t len1 = read_binary("Certificate_AMF_MAYO.bin", cert_AMF, sig_max_len_cert);
    size_t len2 = read_binary("Certificate_BS_MAYO.bin", cert_BS, sig_max_len_cert);

    // Load message
    uint8_t message[MSG_LEN];
    FILE *fmsg = fopen("message.txt", "rb");
    fread(message, 1, MSG_LEN, fmsg);
    fclose(fmsg);
    print_hex("Message", message, MSG_LEN);

    // Load message signature
    uint8_t signature[sig_max_len_msg];
    size_t sig_len = read_binary("signature.bin", signature, sig_max_len_msg);

    double total_time = 0.0;
    double total_time_sig = 0.0;

    for (int i = 0; i < runs; i++) {
        struct timespec ts1, ts2;
        struct timespec ts1sig, ts2sig;
        clock_gettime(CLOCK_MONOTONIC, &ts1);

        int cert1 = OQS_SIG_verify(sig_cert, pk_AMF, pk_len_cert, cert_AMF, len1, pk_CKG);
        int cert2 = OQS_SIG_verify(sig_cert, pk_BS, pk_len_msg, cert_BS, len2, pk_AMF);
        clock_gettime(CLOCK_MONOTONIC, &ts1sig);
        int sig_ok = OQS_SIG_verify(sig_msg, message, MSG_LEN, signature, sig_len, pk_BS);
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

    OQS_SIG_free(sig_cert);
    OQS_SIG_free(sig_msg);
    printf("Average Verification Time: %.9f sec\n", total_time / runs);
    printf("Average One Signature Verification Time: %.9f sec\n", total_time_sig / runs);
    return 0;
}

int main() {
    ue();
}
