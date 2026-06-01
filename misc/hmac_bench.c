#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define NUM_RUNS 1000
#define KEY_SIZE 32
#define MSG_SIZE 79
#define MAC_SIZE 32

int main(void) {
    unsigned char key[KEY_SIZE];
    unsigned char msg[MSG_SIZE];
    unsigned char mac[MAC_SIZE];
    unsigned int mac_len;
    struct timespec start, end;
    double elapsed, total = 0.0;

    /* Fill key and message with dummy data */
    memset(key, 0xAB, KEY_SIZE);
    memset(msg, 0xCD, MSG_SIZE);

    /* Warm-up run */
    HMAC(EVP_sha256(), key, KEY_SIZE, msg, MSG_SIZE, mac, &mac_len);

    for (int i = 0; i < NUM_RUNS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);

        HMAC(EVP_sha256(), key, KEY_SIZE, msg, MSG_SIZE, mac, &mac_len);

        clock_gettime(CLOCK_MONOTONIC, &end);

        elapsed = (end.tv_sec - start.tv_sec) * 1e6 +
                  (end.tv_nsec - start.tv_nsec) / 1e3; /* microseconds */
        total += elapsed;
    }

    printf("HMAC-SHA256 Benchmark (%d runs)\n", NUM_RUNS);
    printf("  Average: %.3f us\n", total / NUM_RUNS);
    printf("  Total:   %.3f us\n", total);
    printf("  MAC len: %u bytes\n", mac_len);

    return 0;
}
