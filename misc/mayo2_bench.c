// Mayo-2 Verification Benchmark
//
// Compile: gcc mayo2_bench.c -o mayo2_bench -loqs -lcrypto -lssl
// Run:     ./mayo2_bench
//
// Measures average verification time over 1000 runs

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define ALG "MAYO-2"
#define MSG_LEN 79
#define RUNS 1000

int main() {
    OQS_SIG *sig = OQS_SIG_new(ALG);
    if (sig == NULL) {
        fprintf(stderr, "Error: %s not available in this liboqs build.\n", ALG);
        return 1;
    }

    size_t pk_len  = sig->length_public_key;
    size_t sk_len  = sig->length_secret_key;
    size_t sig_len = sig->length_signature;

    printf("Algorithm:      %s\n", ALG);
    printf("Public key:     %zu bytes\n", pk_len);
    printf("Secret key:     %zu bytes\n", sk_len);
    printf("Signature:      %zu bytes\n", sig_len);
    printf("Runs:           %d\n\n", RUNS);

    uint8_t *pk        = malloc(pk_len);
    uint8_t *sk        = malloc(sk_len);
    uint8_t *signature = malloc(sig_len);

    // Generate keypair
    OQS_SIG_keypair(sig, pk, sk);

    // Create a 79-byte SIB1 message
    uint8_t message[MSG_LEN];
    memset(message, 0, MSG_LEN);
    memcpy(message, "SIB1: Hello UE, this is your base station broadcast", 52);

    // Sign the message once
    size_t actual_sig_len;
    OQS_SIG_sign(sig, signature, &actual_sig_len, message, MSG_LEN, sk);
    printf("Actual signature length: %zu bytes\n\n", actual_sig_len);

    // Verify once to warm up
    int rc = OQS_SIG_verify(sig, message, MSG_LEN, signature, actual_sig_len, pk);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Error: initial verification failed!\n");
        free(pk); free(sk); free(signature);
        OQS_SIG_free(sig);
        return 1;
    }

    // Benchmark verification
    double total_ns = 0.0;
    double min_ns   = 1e18;
    double max_ns   = 0.0;

    for (int i = 0; i < RUNS; i++) {
        struct timespec ts1, ts2;

        clock_gettime(CLOCK_MONOTONIC, &ts1);
        OQS_SIG_verify(sig, message, MSG_LEN, signature, actual_sig_len, pk);
        clock_gettime(CLOCK_MONOTONIC, &ts2);

        double dt = (ts2.tv_sec - ts1.tv_sec) * 1e9 + (ts2.tv_nsec - ts1.tv_nsec);
        total_ns += dt;
        if (dt < min_ns) min_ns = dt;
        if (dt > max_ns) max_ns = dt;
    }

    double avg_ns = total_ns / RUNS;

    printf("=== Mayo-2 Verification Benchmark ===\n");
    printf("Average: %.3f μs  (%.9f sec)\n", avg_ns / 1e3, avg_ns / 1e9);
    printf("Min:     %.3f μs\n", min_ns / 1e3);
    printf("Max:     %.3f μs\n", max_ns / 1e3);
    printf("Total:   %.3f ms  (for %d runs)\n", total_ns / 1e6, RUNS);

    free(pk);
    free(sk);
    free(signature);
    OQS_SIG_free(sig);
    return 0;
}
