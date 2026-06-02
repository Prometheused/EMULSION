/*****************************************************
 *       EMULSION Framework — BS (Broadcast)         *
 *****************************************************
 * Implements Algorithm 2: EMULSION.Broadcast
 *
 * Compile: gcc BS.c -o BS -loqs -lcrypto -lssl
 * Run:     ./BS [num_benchmark_runs]
 *          Default: 1000 benchmark runs
 *
 * Inputs:  chain.bin, info.bin, cert_K0.bin
 * Outputs: broadcast.bin  — the over-the-air packet stream
 *
 * Broadcast file format:
 *   'E' (epoch-opening): m(79) + i(4) + τ(16) + info_len(4) + info + cert_len(4) + cert
 *   'S' (subsequent):    m(79) + i(4) + τ(16) + K_disc(32)
 ****************************************************/

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define KEY_LEN     32
#define TAG_LEN     16
#define MSG_LEN     79
#define INFO_LEN    48
#define ID_BS_LEN   4

/* Same PRF keys as AMF and UE — must match */
static const uint8_t CHAIN_PRF_KEY[32] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};
static const uint8_t DERIVE_PRF_KEY[32] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf
};

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t out[32]) {
    unsigned int olen = 0;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &olen);
}

/* K'_i = F'(K_i): derive MAC key */
static void derive_Fprime(const uint8_t Ki[KEY_LEN], uint8_t out[32]) {
    hmac_sha256(DERIVE_PRF_KEY, 32, Ki, KEY_LEN, out);
}

/* τ_i = HMAC(K'_i, m || i || ID_BS), truncated to TAG_LEN */
static void compute_tag(const uint8_t mac_key[32],
                        const uint8_t *msg, uint32_t i,
                        uint32_t id_bs, uint8_t tag[TAG_LEN]) {
    /* Build MAC input: m(79) || i(4) || ID_BS(4) = 87 bytes */
    uint8_t buf[MSG_LEN + 4 + ID_BS_LEN];
    memcpy(buf,              msg,    MSG_LEN);
    memcpy(buf + MSG_LEN,    &i,     4);
    memcpy(buf + MSG_LEN + 4, &id_bs, ID_BS_LEN);

    uint8_t full[32];
    hmac_sha256(mac_key, 32, buf, sizeof(buf), full);
    memcpy(tag, full, TAG_LEN);
}

static size_t file_size(const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    size_t sz = (size_t)ftell(f);
    fclose(f);
    return sz;
}

static size_t read_binary(const char *fname, uint8_t *buf, size_t maxlen) {
    FILE *f = fopen(fname, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", fname); exit(1); }
    size_t n = fread(buf, 1, maxlen, f);
    fclose(f);
    return n;
}

static void write_bytes(FILE *out, const void *p, size_t n) {
    fwrite(p, 1, n, out);
}

int main(int argc, char **argv) {
    int bench_runs = 1000;
    if (argc > 1) bench_runs = atoi(argv[1]);

    /* ---- Load chain ---- */
    size_t chain_sz = file_size("chain.bin");
    if (chain_sz == 0) { fprintf(stderr, "Error: chain.bin not found. Run AMF first.\n"); return 1; }
    uint8_t *chain = malloc(chain_sz);
    read_binary("chain.bin", chain, chain_sz);
    uint16_t chain_len = (uint16_t)(chain_sz / KEY_LEN - 1);

    /* ---- Load info ---- */
    uint8_t info[INFO_LEN];
    read_binary("info.bin", info, INFO_LEN);

    /* Parse parameters from info */
    uint32_t id_bs;
    uint16_t d, ell;
    memcpy(&id_bs, info + 32, 4);
    memcpy(&d,     info + 44, 2);
    memcpy(&ell,   info + 46, 2);

    printf("[BS] EMULSION.Broadcast — |C|=%u, d=%u, ID_BS=%u\n", ell, d, id_bs);
    printf("     Benchmark runs: %d\n\n", bench_runs);

    /* ---- Load cert_K0 ---- */
    size_t cert_sz = file_size("cert_K0.bin");
    uint8_t *cert = malloc(cert_sz);
    read_binary("cert_K0.bin", cert, cert_sz);

    /* ---- Create SIB1 message (79 bytes) ---- */
    uint8_t message[MSG_LEN];
    memset(message, 0, MSG_LEN);
    const char *sib1_content = "SIB1: PLMN=00101 CellID=1 TAC=1 CellBarred=no";
    memcpy(message, sib1_content, strlen(sib1_content));

    /* Save message for reference */
    FILE *fmsg = fopen("message.txt", "wb");
    fwrite(message, 1, MSG_LEN, fmsg);
    fclose(fmsg);

    /* ---- Produce broadcast stream ---- */
    FILE *out = fopen("broadcast.bin", "wb");
    if (!out) { fprintf(stderr, "Cannot create broadcast.bin\n"); return 1; }

    printf("[BS] Producing broadcast stream (%u packets):\n", ell);

    for (uint32_t i = 1; i <= ell; i++) {
        /* Step 1: K'_i = F'(K_i) */
        uint8_t mac_key[32];
        derive_Fprime(chain + i * KEY_LEN, mac_key);

        /* Step 2: τ_i = HMAC(K'_i, m || i || ID_BS) */
        uint8_t tag[TAG_LEN];
        compute_tag(mac_key, message, i, id_bs, tag);

        /* Step 3: K_disc = K_{i-d} if i > d, else ⊥ */
        /* For epoch-opening (i=1), K_0 is already in info, so no separate disc */
        int has_kdisc = (i > d) ? 1 : 0;

        if (i == 1) {
            /* ---- Epoch-opening packet ---- */
            /* Π_1 = m || i || τ || info || cert_K0 */
            uint8_t type = 'E';
            write_bytes(out, &type, 1);
            write_bytes(out, message, MSG_LEN);
            uint32_t idx = i;
            write_bytes(out, &idx, 4);
            write_bytes(out, tag, TAG_LEN);
            uint32_t ilen = INFO_LEN;
            write_bytes(out, &ilen, 4);
            write_bytes(out, info, INFO_LEN);
            uint32_t clen = (uint32_t)cert_sz;
            write_bytes(out, &clen, 4);
            write_bytes(out, cert, cert_sz);

            size_t pkt_sz = 1 + MSG_LEN + 4 + TAG_LEN + 4 + INFO_LEN + 4 + cert_sz;
            printf("  P%u [epoch-opening]: %zu B (type=E, info=%d B, cert=%zu B)\n",
                   i, pkt_sz, INFO_LEN, cert_sz);
        } else {
            /* ---- Subsequent packet ---- */
            /* Π_i = m || i || τ || K_disc */
            uint8_t type = 'S';
            write_bytes(out, &type, 1);
            write_bytes(out, message, MSG_LEN);
            uint32_t idx = i;
            write_bytes(out, &idx, 4);
            write_bytes(out, tag, TAG_LEN);
            /* Always include K_disc for subsequent packets */
            uint8_t kdisc[KEY_LEN];
            memcpy(kdisc, chain + (i - d) * KEY_LEN, KEY_LEN);
            write_bytes(out, kdisc, KEY_LEN);

            size_t pkt_sz = 1 + MSG_LEN + 4 + TAG_LEN + KEY_LEN;
            printf("  P%u [subsequent]:    %zu B (K_disc = K_%u)\n",
                   i, pkt_sz, i - d);
        }
    }

    fclose(out);
    printf("\n[BS] Saved broadcast.bin\n\n");

    /* ---- Benchmark per-packet signing cost ---- */
    printf("[BS] Benchmarking per-packet cost (%d runs)...\n", bench_runs);

    double total_ns = 0.0;
    double min_ns = 1e18, max_ns = 0.0;

    for (int r = 0; r < bench_runs; r++) {
        struct timespec ts1, ts2;
        clock_gettime(CLOCK_MONOTONIC, &ts1);

        /* Two HMAC operations per packet: F' + MAC */
        uint8_t mac_key[32];
        derive_Fprime(chain + 1 * KEY_LEN, mac_key);   /* F'(K_1) */

        uint8_t tag[TAG_LEN];
        compute_tag(mac_key, message, 1, id_bs, tag);   /* HMAC tag */

        clock_gettime(CLOCK_MONOTONIC, &ts2);

        double dt = (ts2.tv_sec - ts1.tv_sec) * 1e9 + (ts2.tv_nsec - ts1.tv_nsec);
        total_ns += dt;
        if (dt < min_ns) min_ns = dt;
        if (dt > max_ns) max_ns = dt;
    }

    printf("  Average per-packet signing: %.3f µs\n", total_ns / bench_runs / 1e3);
    printf("  Min: %.3f µs\n", min_ns / 1e3);
    printf("  Max: %.3f µs\n", max_ns / 1e3);
    printf("  (2 HMAC-SHA256 operations per packet)\n");

    free(chain); free(cert);
    return 0;
}
