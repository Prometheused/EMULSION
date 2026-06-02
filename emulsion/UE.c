/*****************************************************
 *       EMULSION Framework — UE (Authenticate)      *
 *****************************************************
 * Implements Algorithm 3: EMULSION.Authenticate
 *
 * Compile: gcc UE.c -o UE -loqs -lcrypto -lssl
 * Run:     ./UE [num_benchmark_runs]
 *          Default: 1000 benchmark runs
 *
 * Inputs:
 *   PK_AMF_MAYO.txt — MAYO-2 public key (from eSIM)
 *   broadcast.bin   — over-the-air packet stream from BS
 *
 * Verification steps per packet:
 *   i=1: MAYO.Verify(PK_AMF, info, cert_K0) → store K_0
 *   All: Security condition check (imax < i + d)
 *        Buffer (m, i, τ_i)
 *        If K_disc: chain check F^j(K_disc) = K_0,
 *                   derive K'_j, verify HMAC → authenticate m_j
 ****************************************************/

#include <oqs/oqs.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define ALG_CERT    "MAYO-2"
#define KEY_LEN     32
#define TAG_LEN     16
#define MSG_LEN     79
#define INFO_LEN    48
#define ID_BS_LEN   4
#define MAX_CHAIN   256  /* max supported chain length */

/* Same PRF keys as AMF and BS */
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

/* One-way chain: K_i = F(K_{i+1}) */
static void chain_F(const uint8_t in[KEY_LEN], uint8_t out[KEY_LEN]) {
    hmac_sha256(CHAIN_PRF_KEY, 32, in, KEY_LEN, out);
}

/* MAC key derivation: K'_i = F'(K_i) */
static void derive_Fprime(const uint8_t Ki[KEY_LEN], uint8_t out[32]) {
    hmac_sha256(DERIVE_PRF_KEY, 32, Ki, KEY_LEN, out);
}

/* Recompute τ_j = HMAC(K'_j, m_j || j || ID_BS) */
static void compute_tag(const uint8_t mac_key[32],
                        const uint8_t *msg, uint32_t j,
                        uint32_t id_bs, uint8_t tag[TAG_LEN]) {
    uint8_t buf[MSG_LEN + 4 + ID_BS_LEN];
    memcpy(buf,              msg,    MSG_LEN);
    memcpy(buf + MSG_LEN,    &j,     4);
    memcpy(buf + MSG_LEN + 4, &id_bs, ID_BS_LEN);

    uint8_t full[32];
    hmac_sha256(mac_key, 32, buf, sizeof(buf), full);
    memcpy(tag, full, TAG_LEN);
}

static int consteq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++) r |= (a[i] ^ b[i]);
    return r == 0;
}

static void read_hex_file(const char *fname, uint8_t *buf, size_t len) {
    FILE *f = fopen(fname, "r");
    if (!f) { fprintf(stderr, "Cannot open %s\n", fname); exit(1); }
    for (size_t i = 0; i < len; i++) fscanf(f, "%2hhx", &buf[i]);
    fclose(f);
}

static void read_bytes(FILE *in, void *p, size_t n) {
    if (fread(p, 1, n, in) != n) {
        fprintf(stderr, "read_bytes: unexpected EOF\n"); exit(1);
    }
}

static uint32_t read_u32(FILE *in) {
    uint32_t x = 0;
    read_bytes(in, &x, 4);
    return x;
}

/* Buffered pending messages */
typedef struct {
    uint8_t  msg[MSG_LEN];
    uint32_t idx;
    uint8_t  tag[TAG_LEN];
    int      present;
    int      authenticated;
} BufferedMsg;

int main(int argc, char **argv) {
    int bench_runs = 1000;
    if (argc > 1) bench_runs = atoi(argv[1]);

    /* ---- Load PK_AMF from eSIM ---- */
    OQS_SIG *sig = OQS_SIG_new(ALG_CERT);
    if (!sig) { fprintf(stderr, "Error: %s not available.\n", ALG_CERT); return 1; }

    uint8_t *pk_amf = malloc(sig->length_public_key);
    read_hex_file("PK_AMF_MAYO.txt", pk_amf, sig->length_public_key);
    printf("[UE] Loaded PK_AMF from eSIM (%zu B)\n\n", sig->length_public_key);

    /* ---- Open broadcast stream ---- */
    FILE *in = fopen("broadcast.bin", "rb");
    if (!in) { fprintf(stderr, "Cannot open broadcast.bin\n"); return 1; }

    /* ---- UE state ---- */
    int       have_anchor = 0;
    uint8_t   K0[KEY_LEN];          /* trusted chain anchor */
    uint32_t  id_bs  = 0;
    uint32_t  t0     = 0;
    uint32_t  t_int  = 0;
    uint16_t  d      = 0;
    uint16_t  ell    = 0;

    BufferedMsg buf_msgs[MAX_CHAIN + 1];
    memset(buf_msgs, 0, sizeof(buf_msgs));

    /* Timing accumulators */
    double mayo_verify_ns = 0.0;
    double hmac_verify_ns = 0.0;
    int    msgs_authenticated = 0;

    /* ---- Process broadcast packets ---- */
    printf("[UE] Processing broadcast stream:\n\n");

    while (1) {
        uint8_t type;
        if (fread(&type, 1, 1, in) != 1) break;  /* EOF */

        if (type == 'E') {
            /* ======= Epoch-opening packet ======= */
            uint8_t  msg[MSG_LEN];
            uint32_t idx;
            uint8_t  tag[TAG_LEN];

            read_bytes(in, msg, MSG_LEN);
            idx = read_u32(in);
            read_bytes(in, tag, TAG_LEN);

            /* Read info */
            uint32_t info_len = read_u32(in);
            uint8_t  info[INFO_LEN];
            read_bytes(in, info, info_len);

            /* Read cert_K0 */
            uint32_t cert_len = read_u32(in);
            uint8_t *cert = malloc(cert_len);
            read_bytes(in, cert, cert_len);

            printf("  P%u [epoch-opening] received\n", idx);

            /* Step (i): MAYO.Verify(PK_AMF, info, cert_K0) */
            struct timespec ts1, ts2;
            clock_gettime(CLOCK_MONOTONIC, &ts1);

            int rc = OQS_SIG_verify(sig, info, info_len, cert, cert_len, pk_amf);

            clock_gettime(CLOCK_MONOTONIC, &ts2);
            mayo_verify_ns = (ts2.tv_sec - ts1.tv_sec) * 1e9 +
                             (ts2.tv_nsec - ts1.tv_nsec);

            if (rc != OQS_SUCCESS) {
                printf("    [FAIL] Anchor certificate not verified — reject\n");
                free(cert);
                continue;
            }
            printf("    [OK]   MAYO.Verify passed (%.3f µs)\n",
                   mayo_verify_ns / 1e3);

            /* Store K_0 and TESLA parameters as trusted state */
            memcpy(K0, info, KEY_LEN);
            memcpy(&id_bs, info + 32, 4);
            memcpy(&t0,    info + 36, 4);
            memcpy(&t_int, info + 40, 4);
            memcpy(&d,     info + 44, 2);
            memcpy(&ell,   info + 46, 2);
            have_anchor = 1;

            printf("    Stored K_0, |C|=%u, d=%u, T_int=%u ms\n", ell, d, t_int);

            /* Buffer (m, i, τ) pending key disclosure */
            if (idx <= MAX_CHAIN) {
                memcpy(buf_msgs[idx].msg, msg, MSG_LEN);
                buf_msgs[idx].idx = idx;
                memcpy(buf_msgs[idx].tag, tag, TAG_LEN);
                buf_msgs[idx].present = 1;
                buf_msgs[idx].authenticated = 0;
            }
            printf("    Buffered (m_%u, τ_%u) pending key disclosure\n\n", idx, idx);

            free(cert);

        } else if (type == 'S') {
            /* ======= Subsequent packet ======= */
            if (!have_anchor) {
                fprintf(stderr, "    [WARN] Subsequent packet before anchor — skip\n");
                /* Skip past the fixed-size subsequent packet data */
                uint8_t skip[MSG_LEN + 4 + TAG_LEN + KEY_LEN];
                read_bytes(in, skip, sizeof(skip));
                continue;
            }

            uint8_t  msg[MSG_LEN];
            uint32_t idx;
            uint8_t  tag[TAG_LEN];
            uint8_t  kdisc[KEY_LEN];

            read_bytes(in, msg, MSG_LEN);
            idx = read_u32(in);
            read_bytes(in, tag, TAG_LEN);
            read_bytes(in, kdisc, KEY_LEN);

            printf("  P%u [subsequent] received (K_disc = K_%u)\n", idx, idx - d);

            /* Buffer this packet's message pending its own key disclosure */
            if (idx <= MAX_CHAIN) {
                memcpy(buf_msgs[idx].msg, msg, MSG_LEN);
                buf_msgs[idx].idx = idx;
                memcpy(buf_msgs[idx].tag, tag, TAG_LEN);
                buf_msgs[idx].present = 1;
                buf_msgs[idx].authenticated = 0;
            }

            /* Authenticate buffered message j = i - d using K_disc */
            uint32_t j = idx - d;

            struct timespec ts1, ts2;
            clock_gettime(CLOCK_MONOTONIC, &ts1);

            /* Step (iv): Chain check — F^j(K_disc) == K_0 */
            uint8_t val[KEY_LEN];
            memcpy(val, kdisc, KEY_LEN);
            for (uint32_t step = 0; step < j; step++) {
                uint8_t tmp[KEY_LEN];
                chain_F(val, tmp);
                memcpy(val, tmp, KEY_LEN);
            }

            if (!consteq(val, K0, KEY_LEN)) {
                clock_gettime(CLOCK_MONOTONIC, &ts2);
                printf("    [FAIL] Chain check: F^%u(K_disc) ≠ K_0\n\n", j);
                continue;
            }

            /* Step (v): Derive K'_j = F'(K_disc) */
            uint8_t mac_key[32];
            derive_Fprime(kdisc, mac_key);

            /* Verify HMAC of buffered message j */
            if (j >= 1 && j <= MAX_CHAIN && buf_msgs[j].present &&
                !buf_msgs[j].authenticated) {

                uint8_t recomputed[TAG_LEN];
                compute_tag(mac_key, buf_msgs[j].msg, j, id_bs, recomputed);

                clock_gettime(CLOCK_MONOTONIC, &ts2);
                double dt = (ts2.tv_sec - ts1.tv_sec) * 1e9 +
                            (ts2.tv_nsec - ts1.tv_nsec);
                hmac_verify_ns += dt;

                if (consteq(recomputed, buf_msgs[j].tag, TAG_LEN)) {
                    buf_msgs[j].authenticated = 1;
                    msgs_authenticated++;
                    printf("    [OK]   m_%u authenticated (%.3f µs)\n",
                           j, dt / 1e3);

                    /* Print authenticated message content */
                    size_t n = MSG_LEN;
                    while (n > 0 && buf_msgs[j].msg[n-1] == 0) n--;
                    printf("           \"%.*s\"\n\n", (int)n, buf_msgs[j].msg);
                } else {
                    printf("    [FAIL] MAC mismatch for m_%u\n\n", j);
                }
            } else {
                clock_gettime(CLOCK_MONOTONIC, &ts2);
                printf("    No buffered message at j=%u to authenticate\n\n", j);
            }

        } else {
            fprintf(stderr, "Unknown packet type 0x%02X\n", type);
            break;
        }
    }

    fclose(in);

    /* ---- Summary ---- */
    printf("===== EMULSION Verification Summary =====\n");
    printf("Chain length |C| = %u, d = %u\n", ell, d);
    printf("Messages authenticated: %d / %u\n", msgs_authenticated, ell);
    if (ell > 0 && !buf_msgs[ell].authenticated) {
        printf("  (m_%u pending — key disclosed in next epoch)\n", ell);
    }
    printf("\nTiming:\n");
    printf("  MAYO-2 anchor verify: %.3f µs (one-time)\n", mayo_verify_ns / 1e3);
    printf("  HMAC chain+verify:    %.3f µs (total for %d msgs)\n",
           hmac_verify_ns / 1e3, msgs_authenticated);
    if (msgs_authenticated > 0)
        printf("  Avg per-msg HMAC:     %.3f µs\n",
               hmac_verify_ns / msgs_authenticated / 1e3);
    printf("  Total crypto time:    %.3f µs\n",
           (mayo_verify_ns + hmac_verify_ns) / 1e3);
    printf("  SIB1 period:          %u ms (= %u µs)\n",
           t_int, t_int * 1000);
    printf("  Crypto / SIB1 period: %.4f%%\n",
           (mayo_verify_ns + hmac_verify_ns) / (t_int * 1e6) * 100.0);

    /* ---- Benchmark HMAC verification ---- */
    printf("\n[UE] Benchmarking HMAC verification (%d runs)...\n", bench_runs);

    /* Use K_1 from chain check as a test key */
    double bench_total = 0.0, bench_min = 1e18, bench_max = 0.0;
    uint8_t dummy_key[KEY_LEN];
    memset(dummy_key, 0x42, KEY_LEN);

    for (int r = 0; r < bench_runs; r++) {
        struct timespec t1, t2;
        uint8_t mk[32], tg[TAG_LEN];

        clock_gettime(CLOCK_MONOTONIC, &t1);

        /* Chain check (1 HMAC) + key derivation (1 HMAC) + tag verify (1 HMAC) */
        uint8_t chain_out[KEY_LEN];
        chain_F(dummy_key, chain_out);
        derive_Fprime(dummy_key, mk);
        compute_tag(mk, buf_msgs[1].msg, 1, id_bs, tg);

        clock_gettime(CLOCK_MONOTONIC, &t2);

        double dt = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec);
        bench_total += dt;
        if (dt < bench_min) bench_min = dt;
        if (dt > bench_max) bench_max = dt;
    }

    printf("  Average (3 HMACs): %.3f µs\n", bench_total / bench_runs / 1e3);
    printf("  Min: %.3f µs\n", bench_min / 1e3);
    printf("  Max: %.3f µs\n", bench_max / 1e3);

    free(pk_amf);
    OQS_SIG_free(sig);
    return 0;
}
