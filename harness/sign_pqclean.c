/* sign_pqclean.c — signing cost + correctness for one signature parameter
 * set via the PQClean "clean" reference implementation.
 *
 * Compile once per parameter set, e.g.:
 *   gcc -O2 -std=c99 -Wall -I<clean-dir> -I<pqclean>/common -DPQ_SIG \
 *       -DPREFIX=PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN \
 *       -DPQCLEAN_COMMIT="0586a824..." \
 *       sign_pqclean.c <clean sources...> <pqclean>/common/fips202.c \
 *       <pqclean>/common/sha2.c <pqclean>/common/randombytes.c \
 *       -o sign_pqclean_sphincs_shake_128s
 * (see harness/build_signing.sh for the exact per-set source lists)
 *
 * Method: correctness first (sign/verify round-trip, tampered signature
 * rejected), then keygen/sign/verify each timed as the median of 11
 * single-shot measurements (clock_gettime(CLOCK_MONOTONIC)), because
 * SLH-DSA signing is slow (~10-100 ms) and tight loops would take minutes.
 * The signed message is a fixed 64-byte manifest-style string, the same
 * shape as the liboqs driver's benchmark message.
 *
 * Output: human-readable lines to stdout (captured verbatim as the raw
 * log) and a one-entry JSON document to the file named by --json.
 * Exit 0 = correctness pass; 1 = correctness fail; 2 = build/usage error.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "api.h"

#define ITERS 11
#define MSG "PFTL release-signing benchmark message, 64 bytes: 0123456789abcde"

#define CAT2(a, b) a##b
#define XCAT(a, b) CAT2(a, b)
#define FN(name) XCAT(PREFIX, name)
#define SZ(name) XCAT(PREFIX, name)

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}
static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static double median(double *v, int n) {
    qsort(v, (size_t)n, sizeof(double), cmp_dbl);
    return v[n / 2];
}

int main(int argc, char **argv) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json") && i + 1 < argc) json_path = argv[++i];
    const char *alg = SZ(_CRYPTO_ALGNAME);
    printf("--- %s (PQClean clean, commit %s) ---\n", alg, PQCLEAN_COMMIT);
    printf("  sizes: pk=%d sk=%d sig=%d\n",
           SZ(_CRYPTO_PUBLICKEYBYTES), SZ(_CRYPTO_SECRETKEYBYTES),
           SZ(_CRYPTO_BYTES));
    uint8_t *pk = malloc(SZ(_CRYPTO_PUBLICKEYBYTES));
    uint8_t *sk = malloc(SZ(_CRYPTO_SECRETKEYBYTES));
    uint8_t *sg = malloc(SZ(_CRYPTO_BYTES));
    const uint8_t *msg = (const uint8_t *)MSG;
    size_t msglen = strlen(MSG);
    if (!pk || !sk || !sg) return 2;

    int ok = 1;
    if (FN(_crypto_sign_keypair)(pk, sk) != 0) { printf("  CORRECTNESS FAIL: keypair\n"); ok = 0; }
    size_t sglen = 0;
    if (FN(_crypto_sign_signature)(sg, &sglen, msg, msglen, sk) != 0) { printf("  CORRECTNESS FAIL: sign\n"); ok = 0; }
    if (FN(_crypto_sign_verify)(sg, sglen, msg, msglen, pk) != 0) { printf("  CORRECTNESS FAIL: verify(valid)\n"); ok = 0; }
    sg[0] ^= 0x01;
    if (FN(_crypto_sign_verify)(sg, sglen, msg, msglen, pk) == 0) { printf("  CORRECTNESS FAIL: verify(tampered) accepted\n"); ok = 0; }
    sg[0] ^= 0x01;
    printf("  correctness: %s (sign/verify round-trip, tampered signature rejected; sig_len=%zu)\n",
           ok ? "PASS" : "FAIL", sglen);

    double t[ITERS], kg, sn, vf;
    for (int i = 0; i < ITERS; i++) {
        double a = now_us(); FN(_crypto_sign_keypair)(pk, sk); t[i] = now_us() - a;
    }
    kg = median(t, ITERS);
    for (int i = 0; i < ITERS; i++) {
        double a = now_us();
        size_t l = 0; FN(_crypto_sign_signature)(sg, &l, msg, msglen, sk);
        t[i] = now_us() - a; sglen = l;
    }
    sn = median(t, ITERS);
    for (int i = 0; i < ITERS; i++) {
        double a = now_us(); FN(_crypto_sign_verify)(sg, sglen, msg, msglen, pk); t[i] = now_us() - a;
    }
    vf = median(t, ITERS);
    printf("  keygen: median=%.3f us/op (n=%d)\n", kg, ITERS);
    printf("  sign:   median=%.3f us/op (n=%d)\n", sn, ITERS);
    printf("  verify: median=%.3f us/op (n=%d)\n", vf, ITERS);

    if (json_path) {
        FILE *jf = fopen(json_path, "w");
        if (!jf) { fprintf(stderr, "cannot open %s\n", json_path); return 2; }
        fprintf(jf, "{\n  \"implementation\": \"pqclean\",\n  \"pqclean_commit\": \"%s\",\n  \"results\": [\n    {\"algorithm\": \"%s\", \"type\": \"sig\","
                "\"pk_bytes\": %d, \"sk_bytes\": %d, \"sig_bytes\": %d,"
                " \"correctness\": \"%s\","
                " \"keygen_us\": {\"median\": %.3f},"
                " \"sign_us\": {\"median\": %.3f},"
                " \"verify_us\": {\"median\": %.3f}}\n  ]\n}\n",
                PQCLEAN_COMMIT, alg,
                SZ(_CRYPTO_PUBLICKEYBYTES), SZ(_CRYPTO_SECRETKEYBYTES),
                SZ(_CRYPTO_BYTES), ok ? "PASS" : "FAIL", kg, sn, vf);
        fclose(jf);
        printf("json written to %s\n", json_path);
    }
    printf("RESULT: %s (exit %d)\n", ok ? "PASS" : "FAIL", ok ? 0 : 1);
    return ok ? 0 : 1;
}
