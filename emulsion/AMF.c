/*****************************************************
 *         EMULSION Framework — AMF (Setup)          *
 *****************************************************
 * Implements Algorithm 1: EMULSION.Setup
 *
 * Compile: gcc AMF.c -o AMF -loqs -lcrypto -lssl
 * Run:     ./AMF [chain_length] [d]
 *          Default: chain_length=2, d=1
 *
 * Outputs:
 *   PK_AMF_MAYO.txt  — MAYO-2 public key (hex, for UE eSIM)
 *   chain.bin         — Key chain K_0..K_ℓ (binary, for BS)
 *   info.bin          — info = K_0 || ID_BS || T_0 || T_int || d || ℓ
 *   cert_K0.bin       — MAYO.Sign(sk_AMF, info)
 ****************************************************/

#include <oqs/oqs.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ALG_CERT    "MAYO-2"
#define KEY_LEN     32
#define INFO_LEN    48   /* K0(32) + ID_BS(4) + T0(4) + T_int(4) + d(2) + ℓ(2) */

/* PRF key for one-way chain: K_i = F(K_{i+1}) */
static const uint8_t CHAIN_PRF_KEY[32] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t out[32]) {
    unsigned int olen = 0;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &olen);
}

/* One-way chain function: K_i = chain_F(K_{i+1}) */
static void chain_F(const uint8_t in[KEY_LEN], uint8_t out[KEY_LEN]) {
    hmac_sha256(CHAIN_PRF_KEY, 32, in, KEY_LEN, out);
}

static void write_hex_file(const char *fname, const uint8_t *data, size_t len) {
    FILE *f = fopen(fname, "w");
    for (size_t i = 0; i < len; i++) fprintf(f, "%02X", data[i]);
    fprintf(f, "\n");
    fclose(f);
}

static void save_binary(const char *fname, const uint8_t *data, size_t len) {
    FILE *f = fopen(fname, "wb");
    fwrite(data, 1, len, f);
    fclose(f);
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
    printf("----------------------------------\n");
}

int main(int argc, char **argv) {
    uint16_t chain_len = 2;   /* |C| — default */
    uint16_t d = 1;           /* disclosure delay — default */

    if (argc > 1) chain_len = (uint16_t)atoi(argv[1]);
    if (argc > 2) d = (uint16_t)atoi(argv[2]);

    printf("[AMF] EMULSION.Setup — chain length |C|=%u, d=%u\n\n", chain_len, d);

    /* ---- Step 1: MAYO-2 key generation ---- */
    OQS_SIG *sig = OQS_SIG_new(ALG_CERT);
    if (!sig) { fprintf(stderr, "Error: %s not available.\n", ALG_CERT); return 1; }

    uint8_t *pk_amf = malloc(sig->length_public_key);
    uint8_t *sk_amf = malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig, pk_amf, sk_amf);

    printf("[AMF] MAYO-2 keypair generated.\n");
    printf("  PK size: %zu B\n", sig->length_public_key);
    printf("  SK size: %zu B\n\n", sig->length_secret_key);

    /* ---- Step 2: Generate one-way key chain ---- */
    /* K_ℓ ← random, K_i ← F(K_{i+1}) for i = ℓ-1 down to 0 */
    uint8_t *chain = malloc((chain_len + 1) * KEY_LEN);

    /* K_ℓ = random terminal key */
    RAND_bytes(chain + chain_len * KEY_LEN, KEY_LEN);

    /* Derive chain backwards */
    for (int i = chain_len - 1; i >= 0; i--) {
        chain_F(chain + (i + 1) * KEY_LEN, chain + i * KEY_LEN);
    }

    printf("[AMF] Key chain generated:\n");
    for (int i = 0; i <= chain_len; i++) {
        char label[32];
        snprintf(label, sizeof(label), "  K_%d", i);
        print_hex(label, chain + i * KEY_LEN, KEY_LEN);
    }

    /* ---- Step 3: Build info ---- */
    /* info = K_0 || ID_BS || T_0 || T_int || d || ℓ */
    uint8_t info[INFO_LEN];
    memset(info, 0, INFO_LEN);

    memcpy(info,      chain, KEY_LEN);          /* K_0 (32 B) */
    uint32_t id_bs  = 1;                        /* BS identity */
    uint32_t t0     = 0;                        /* Epoch start time */
    uint32_t t_int  = 160;                      /* 160 ms SIB1 periodicity */
    memcpy(info + 32, &id_bs, 4);
    memcpy(info + 36, &t0,    4);
    memcpy(info + 40, &t_int, 4);
    memcpy(info + 44, &d,     2);
    memcpy(info + 46, &chain_len, 2);

    print_hex("[AMF] info", info, INFO_LEN);

    /* ---- Step 4: cert_K0 ← MAYO.Sign(sk_AMF, info) ---- */
    uint8_t *cert = malloc(sig->length_signature);
    size_t cert_len;
    OQS_SIG_sign(sig, cert, &cert_len, info, INFO_LEN, sk_amf);

    printf("[AMF] cert_K0 signed (%zu bytes)\n\n", cert_len);

    /* ---- Step 5: Save outputs ---- */
    write_hex_file("PK_AMF_MAYO.txt", pk_amf, sig->length_public_key);
    printf("[AMF] Saved PK_AMF_MAYO.txt (%zu B) — provision to UE eSIM\n",
           sig->length_public_key);

    save_binary("chain.bin", chain, (chain_len + 1) * KEY_LEN);
    printf("[AMF] Saved chain.bin (%u keys, %u B)\n",
           chain_len + 1, (chain_len + 1) * KEY_LEN);

    save_binary("info.bin", info, INFO_LEN);
    printf("[AMF] Saved info.bin (%d B)\n", INFO_LEN);

    save_binary("cert_K0.bin", cert, cert_len);
    printf("[AMF] Saved cert_K0.bin (%zu B)\n\n", cert_len);

    printf("[AMF] Setup complete. Provision (chain.bin, info.bin, cert_K0.bin) to BS over N2.\n");

    free(pk_amf); free(sk_amf); free(chain); free(cert);
    OQS_SIG_free(sig);
    return 0;
}
