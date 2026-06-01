// 
// 
/**************************************
 *          Dilithium Algorithm            *
 **************************************
 *
 *Compile:          gcc BS.c -o BS -loqs -lcrypto -lssl
 * 
 *Run:              ./BS
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

void write_binary(const char *fname, const uint8_t *data, size_t len) {
    FILE *f = fopen(fname, "wb");
    fwrite(data, 1, len, f);
    fclose(f);
}

void bs(){
    int runs;
    printf("Enter number of signing runs: ");
    scanf("%d", &runs);

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

int main() {
    bs();
}
