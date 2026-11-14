/* sign_release.c — release-signing assessment harness (liboqs + OpenSSL).
 *
 * Signs a synthetic release manifest with several schemes, measures
 * keygen/sign/verify costs, and runs negative tests + a key-rotation drill.
 *
 * Schemes (liboqs 0.16.0, minimal build with SLH-DSA enabled; OpenSSL 3.0.13
 * for Ed25519):
 *   ed25519            (OpenSSL)      classical baseline
 *   ml-dsa-65          (liboqs)       ML-DSA-65, FIPS 204
 *   slh-dsa-sha2-128s  (liboqs)       SLH-DSA-SHA2-128s, FIPS 205
 *   slh-dsa-shake-128s (liboqs)       SLH-DSA-SHAKE-128s, FIPS 205
 *   slh-dsa-sha2-128f  (liboqs)       SLH-DSA-SHA2-128f, FIPS 205
 *   slh-dsa-shake-128f (liboqs)       SLH-DSA-SHAKE-128f, FIPS 205
 *   hybrid-ed25519-mldsa65 (OpenSSL + liboqs) both signatures over the same
 *       manifest; verification requires BOTH to be valid.
 *
 * Keys are ephemeral test-only keys generated fresh on every run and never
 * written to disk. Timings vary run to run; sizes and pass/fail outcomes are
 * deterministic.
 *
 * Usage: sign_release  (stdout = JSON results, stderr = human log)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define KEYGEN_ITERS 5
#define SIGN_ITERS 11
#define ARTIFACT_BYTES (1024 * 1024)
#define MAX_SIG 20000
#define MAX_PK 4096
#define MAX_SK 8192

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
static void hex(const uint8_t *b, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = '\0';
}

/* ---- Ed25519 via OpenSSL EVP ---- */
typedef struct { EVP_PKEY *pkey; uint8_t pk[32]; uint8_t sk[32]; } ed_key;
static int ed_keygen(ed_key *k) {
    k->pkey = NULL; /* EVP_PKEY_keygen frees a non-NULL *pkey first */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_keygen(ctx, &k->pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);
    size_t n = 32;
    if (EVP_PKEY_get_raw_private_key(k->pkey, k->sk, &n) <= 0) return -1;
    n = 32;
    if (EVP_PKEY_get_raw_public_key(k->pkey, k->pk, &n) <= 0) return -1;
    return 0;
}
static int ed_sign(ed_key *k, const uint8_t *msg, size_t msglen,
                   uint8_t *sig, size_t *siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int r = -1;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, k->pkey) == 1)
        if (EVP_DigestSign(ctx, sig, siglen, msg, msglen) == 1) r = 0;
    EVP_MD_CTX_free(ctx);
    return r;
}
static int ed_verify(ed_key *k, const uint8_t *msg, size_t msglen,
                     const uint8_t *sig, size_t siglen) {
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, k->pk, 32);
    if (!pub) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pub); return -1; }
    int r = -1;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) == 1)
        r = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return r; /* 1 = valid, 0 = invalid, -1 = error */
}

/* ---- manifest ---- */
static int build_manifest(char *buf, size_t cap, const char *artifact,
                          uint32_t version, const char *art_sha256,
                          const char *key_id, long not_after) {
    return snprintf(buf, cap,
        "PFTL-RELEASE-MANIFEST-v1\n"
        "artifact=%s\n"
        "version=%u\n"
        "artifact_sha256=%s\n"
        "key_id=%s\n"
        "not_after=%ld\n",
        artifact, version, art_sha256, key_id, not_after);
}

/* verification policy: returns 0 = accept, else reason code */
enum { V_OK = 0, V_REVOKED = 1, V_ROLLBACK = 2, V_EXPIRED = 3, V_BADSIG = 4 };
static const char *v_reason(int r) {
    switch (r) {
        case V_OK: return "accept";
        case V_REVOKED: return "revoked-key";
        case V_ROLLBACK: return "rollback";
        case V_EXPIRED: return "expired-key";
        case V_BADSIG: return "bad-signature";
        default: return "unknown";
    }
}

/* hybrid verify: both Ed25519 and ML-DSA-65 signatures must be valid */
static int hybrid_verify(OQS_SIG *mldsa, const uint8_t *ml_pk,
                         ed_key *ed, const uint8_t *msg, size_t msglen,
                         const uint8_t *ed_sig, const uint8_t *ml_sig,
                         size_t ml_siglen) {
    if (ed_verify(ed, msg, msglen, ed_sig, 64) != 1) return V_BADSIG;
    if (OQS_SIG_verify(mldsa, msg, msglen, ml_sig, ml_siglen, ml_pk) != OQS_SUCCESS)
        return V_BADSIG;
    return V_OK;
}
static int policy_check(const char *key_id, const char *const *revoked, int nrev,
                        uint32_t version, uint32_t installed, long not_after,
                        long now) {
    for (int i = 0; i < nrev; i++)
        if (strcmp(key_id, revoked[i]) == 0) return V_REVOKED;
    if (version <= installed) return V_ROLLBACK;
    if (now >= not_after) return V_EXPIRED;
    return V_OK;
}

/* ---- timing helper for one OQS scheme ---- */
typedef struct {
    const char *name; const char *alg; const char *impl;
    size_t pk, sk, sig;
    double keygen_us, sign_us, verify_us;
    int correctness; /* 1 = sign+verify round-trip passed */
} scheme_result;

static int bench_oqs(const char *name, const char *alg, scheme_result *out) {
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { fprintf(stderr, "%s: OQS_SIG_new failed\n", name); return -1; }
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *sg = malloc(sig->length_signature);
    static const uint8_t msg[] =
        "PFTL-RELEASE-MANIFEST-v1\nartifact=bench\nversion=1\n";
    double t[16];
    for (int i = 0; i < KEYGEN_ITERS; i++) {
        double s = now_us();
        if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) { free(pk); free(sk); free(sg); OQS_SIG_free(sig); return -1; }
        t[i] = now_us() - s;
    }
    double kg = median(t, KEYGEN_ITERS);
    size_t sglen = 0;
    if (OQS_SIG_sign(sig, sg, &sglen, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) {
        free(pk); free(sk); free(sg); OQS_SIG_free(sig); return -1;
    }
    int ok = (OQS_SIG_verify(sig, msg, sizeof(msg) - 1, sg, sglen, pk) == OQS_SUCCESS);
    for (int i = 0; i < SIGN_ITERS; i++) {
        double s = now_us();
        OQS_SIG_sign(sig, sg, &sglen, msg, sizeof(msg) - 1, sk);
        t[i] = now_us() - s;
    }
    double sn = median(t, SIGN_ITERS);
    for (int i = 0; i < SIGN_ITERS; i++) {
        double s = now_us();
        OQS_SIG_verify(sig, msg, sizeof(msg) - 1, sg, sglen, pk);
        t[i] = now_us() - s;
    }
    double vf = median(t, SIGN_ITERS);
    out->name = name; out->alg = alg; out->impl = "liboqs 0.16.0";
    out->pk = sig->length_public_key; out->sk = sig->length_secret_key;
    out->sig = sig->length_signature;
    out->keygen_us = kg; out->sign_us = sn; out->verify_us = vf;
    out->correctness = ok;
    fprintf(stderr, "%s: pk=%zu sk=%zu sig=%zu keygen=%.3f sign=%.3f verify=%.3f us, roundtrip=%s\n",
            name, out->pk, out->sk, out->sig, kg, sn, vf, ok ? "PASS" : "FAIL");
    free(pk); free(sk); free(sg);
    OQS_SIG_free(sig);
    return ok ? 0 : -1;
}

int main(void) {
    fprintf(stderr, "sign_release: liboqs + OpenSSL release-signing harness\n");
    fprintf(stderr, "host: gcc 13.3.0, liboqs 0.16.0 (minimal build, ML-DSA + SLH-DSA), OpenSSL 3.0.13\n");

    /* --- deterministic 1 MiB test artifact + SHA-256 --- */
    uint8_t *artifact = malloc(ARTIFACT_BYTES);
    for (size_t i = 0; i < ARTIFACT_BYTES; i++) artifact[i] = (uint8_t)(i & 0xff);
    double s = now_us();
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(artifact, ARTIFACT_BYTES, digest);
    double hash_us = now_us() - s;
    char art_hex[65]; hex(digest, SHA256_DIGEST_LENGTH, art_hex);
    fprintf(stderr, "artifact: 1 MiB deterministic payload, sha256=%s, hash_time=%.3f us\n", art_hex, hash_us);

    /* --- benchmark each OQS scheme --- */
    scheme_result r[6];
    const char *names[6] = {"ml-dsa-65", "slh-dsa-sha2-128s", "slh-dsa-shake-128s",
                            "slh-dsa-sha2-128f", "slh-dsa-shake-128f", NULL};
    const char *algs[6] = {"ML-DSA-65", "SLH_DSA_PURE_SHA2_128S", "SLH_DSA_PURE_SHAKE_128S",
                           "SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHAKE_128F", NULL};
    int n_oqs = 5, all_ok = 1;
    for (int i = 0; i < n_oqs; i++)
        if (bench_oqs(names[i], algs[i], &r[i]) != 0) all_ok = 0;

    /* --- Ed25519 baseline --- */
    ed_key ed;
    if (ed_keygen(&ed) != 0) { fprintf(stderr, "ed25519 keygen FAILED\n"); return 1; }
    static const uint8_t edmsg[] = "PFTL-RELEASE-MANIFEST-v1\nartifact=bench\nversion=1\n";
    uint8_t edsig[64]; size_t edsiglen = 64;
    if (ed_sign(&ed, edmsg, sizeof(edmsg) - 1, edsig, &edsiglen) != 0) {
        fprintf(stderr, "ed25519 sign FAILED\n"); return 1;
    }
    int ed_ok = (ed_verify(&ed, edmsg, sizeof(edmsg) - 1, edsig, edsiglen) == 1);
    double t[16];
    for (int i = 0; i < KEYGEN_ITERS; i++) {
        ed_key tmp; double a = now_us(); ed_keygen(&tmp); t[i] = now_us() - a;
        EVP_PKEY_free(tmp.pkey);
    }
    double ed_kg = median(t, KEYGEN_ITERS);
    for (int i = 0; i < SIGN_ITERS; i++) {
        size_t l = 64; double a = now_us(); ed_sign(&ed, edmsg, sizeof(edmsg) - 1, edsig, &l); t[i] = now_us() - a;
    }
    double ed_sn = median(t, SIGN_ITERS);
    for (int i = 0; i < SIGN_ITERS; i++) {
        double a = now_us(); ed_verify(&ed, edmsg, sizeof(edmsg) - 1, edsig, edsiglen); t[i] = now_us() - a;
    }
    double ed_vf = median(t, SIGN_ITERS);
    fprintf(stderr, "ed25519: pk=32 sk=32 sig=64 keygen=%.3f sign=%.3f verify=%.3f us, roundtrip=%s\n",
            ed_kg, ed_sn, ed_vf, ed_ok ? "PASS" : "FAIL");
    if (!ed_ok) all_ok = 0;

    /* --- hybrid: Ed25519 + ML-DSA-65 over one manifest --- */
    OQS_SIG *mldsa = OQS_SIG_new("ML-DSA-65");
    uint8_t *ml_pk = malloc(mldsa->length_public_key);
    uint8_t *ml_sk = malloc(mldsa->length_secret_key);
    uint8_t *ml_sg = malloc(mldsa->length_signature);
    OQS_SIG_keypair(mldsa, ml_pk, ml_sk);
    long now = (long)time(NULL);
    char key_id[17]; { uint8_t fp[SHA256_DIGEST_LENGTH]; SHA256(ml_pk, mldsa->length_public_key, fp); hex(fp, 8, key_id); }
    char man[1024];
    int manlen = build_manifest(man, sizeof(man), "postfiatd-testnet-full-1.0.9.tar.gz",
                                3, art_hex, key_id, now + 365L * 86400);
    size_t ml_sglen = 0;
    uint8_t h_ed[64]; size_t h_edlen = 64;
    ed_sign(&ed, (uint8_t *)man, (size_t)manlen, h_ed, &h_edlen);
    OQS_SIG_sign(mldsa, ml_sg, &ml_sglen, (uint8_t *)man, (size_t)manlen, ml_sk);
    int hyb_ok = (hybrid_verify(mldsa, ml_pk, &ed, (uint8_t *)man, (size_t)manlen,
                                h_ed, ml_sg, ml_sglen) == V_OK);
    for (int i = 0; i < SIGN_ITERS; i++) {
        size_t l = 64, ml = 0; double a = now_us();
        ed_sign(&ed, (uint8_t *)man, (size_t)manlen, h_ed, &l);
        OQS_SIG_sign(mldsa, ml_sg, &ml, (uint8_t *)man, (size_t)manlen, ml_sk);
        t[i] = now_us() - a;
    }
    double hyb_sn = median(t, SIGN_ITERS);
    for (int i = 0; i < SIGN_ITERS; i++) {
        double a = now_us();
        hybrid_verify(mldsa, ml_pk, &ed, (uint8_t *)man, (size_t)manlen, h_ed, ml_sg, ml_sglen);
        t[i] = now_us() - a;
    }
    double hyb_vf = median(t, SIGN_ITERS);
    fprintf(stderr, "hybrid ed25519+ml-dsa-65: sig=%zu (64+3309) sign=%.3f verify=%.3f us, roundtrip=%s\n",
            (size_t)(64 + ml_sglen), hyb_sn, hyb_vf, hyb_ok ? "PASS" : "FAIL");
    if (!hyb_ok) all_ok = 0;

    /* --- negative tests (hybrid scheme) --- */
    typedef struct { const char *id; const char *desc; int expected; int got; int pass; } ntest;
    ntest nt[12]; int nnt = 0;
    char man2[1024]; uint8_t sig_tamper[MAX_SIG]; uint8_t ed_tamper[64];
    /* N1: tampered manifest byte */
    memcpy(man2, man, (size_t)manlen); man2[60] ^= 0x01;
    nt[nnt++] = (ntest){"N1", "tampered manifest byte (hybrid)", V_BADSIG,
        hybrid_verify(mldsa, ml_pk, &ed, (uint8_t *)man2, (size_t)manlen, h_ed, ml_sg, ml_sglen), 0};
    /* N2: tampered ML-DSA signature byte */
    memcpy(sig_tamper, ml_sg, ml_sglen); sig_tamper[10] ^= 0x01;
    nt[nnt++] = (ntest){"N2", "tampered ML-DSA-65 signature byte (hybrid)", V_BADSIG,
        hybrid_verify(mldsa, ml_pk, &ed, (uint8_t *)man, (size_t)manlen, h_ed, sig_tamper, ml_sglen), 0};
    /* N3: tampered Ed25519 signature byte */
    memcpy(ed_tamper, h_ed, 64); ed_tamper[5] ^= 0x01;
    nt[nnt++] = (ntest){"N3", "tampered Ed25519 signature byte (hybrid)", V_BADSIG,
        hybrid_verify(mldsa, ml_pk, &ed, (uint8_t *)man, (size_t)manlen, ed_tamper, ml_sg, ml_sglen), 0};
    /* N4: wrong public key (fresh ML-DSA keypair) */
    uint8_t *ml_pk2 = malloc(mldsa->length_public_key);
    uint8_t *ml_sk2 = malloc(mldsa->length_secret_key);
    OQS_SIG_keypair(mldsa, ml_pk2, ml_sk2);
    nt[nnt++] = (ntest){"N4", "wrong ML-DSA-65 public key (hybrid)", V_BADSIG,
        hybrid_verify(mldsa, ml_pk2, &ed, (uint8_t *)man, (size_t)manlen, h_ed, ml_sg, ml_sglen), 0};
    /* N5: rollback — manifest version 2, installed version 3 */
    nt[nnt++] = (ntest){"N5", "rollback: manifest version 2, installed 3", V_ROLLBACK,
        policy_check(key_id, NULL, 0, 2, 3, now + 365L * 86400, now), 0};
    /* N6: revoked key */
    const char *rev1[1] = { key_id };
    nt[nnt++] = (ntest){"N6", "revoked key_id", V_REVOKED,
        policy_check(key_id, rev1, 1, 3, 2, now + 365L * 86400, now), 0};
    /* N7: expired key (not_after in the past) */
    nt[nnt++] = (ntest){"N7", "expired key (not_after in past)", V_EXPIRED,
        policy_check(key_id, NULL, 0, 3, 2, now - 3600, now), 0};
    /* N8: clean manifest passes policy */
    nt[nnt++] = (ntest){"N8", "clean manifest passes policy (control)", V_OK,
        policy_check(key_id, NULL, 0, 3, 2, now + 365L * 86400, now), 0};
    /* N9-N12: same four crypto/policy negatives for SLH-DSA-SHA2-128s */
    OQS_SIG *slh = OQS_SIG_new("SLH_DSA_PURE_SHA2_128S");
    uint8_t *s_pk = malloc(slh->length_public_key);
    uint8_t *s_sk = malloc(slh->length_secret_key);
    uint8_t *s_sg = malloc(slh->length_signature);
    OQS_SIG_keypair(slh, s_pk, s_sk);
    size_t s_sglen = 0;
    OQS_SIG_sign(slh, s_sg, &s_sglen, (uint8_t *)man, (size_t)manlen, s_sk);
    int s_ok = (OQS_SIG_verify(slh, (uint8_t *)man, (size_t)manlen, s_sg, s_sglen, s_pk) == OQS_SUCCESS);
    memcpy(man2, man, (size_t)manlen); man2[60] ^= 0x01;
    int s_n1 = (OQS_SIG_verify(slh, (uint8_t *)man2, (size_t)manlen, s_sg, s_sglen, s_pk) == OQS_SUCCESS) ? V_OK : V_BADSIG;
    memcpy(sig_tamper, s_sg, s_sglen); sig_tamper[100] ^= 0x01;
    int s_n2 = (OQS_SIG_verify(slh, (uint8_t *)man, (size_t)manlen, sig_tamper, s_sglen, s_pk) == OQS_SUCCESS) ? V_OK : V_BADSIG;
    uint8_t *s_pk2 = malloc(slh->length_public_key);
    uint8_t *s_sk2 = malloc(slh->length_secret_key);
    OQS_SIG_keypair(slh, s_pk2, s_sk2);
    int s_n3 = (OQS_SIG_verify(slh, (uint8_t *)man, (size_t)manlen, s_sg, s_sglen, s_pk2) == OQS_SUCCESS) ? V_OK : V_BADSIG;
    nt[nnt++] = (ntest){"N9", "SLH-DSA-SHA2-128s control verify", V_OK, s_ok ? V_OK : V_BADSIG, 0};
    nt[nnt++] = (ntest){"N10", "SLH-DSA-SHA2-128s tampered manifest byte", V_BADSIG, s_n1, 0};
    nt[nnt++] = (ntest){"N11", "SLH-DSA-SHA2-128s tampered signature byte", V_BADSIG, s_n2, 0};
    nt[nnt++] = (ntest){"N12", "SLH-DSA-SHA2-128s wrong public key", V_BADSIG, s_n3, 0};
    for (int i = 0; i < nnt; i++) {
        nt[i].pass = (nt[i].expected == nt[i].got);
        fprintf(stderr, "%s %s: expected=%s got=%s %s\n", nt[i].id, nt[i].desc,
                v_reason(nt[i].expected), v_reason(nt[i].got), nt[i].pass ? "PASS" : "FAIL");
        if (!nt[i].pass) all_ok = 0;
    }

    /* --- rotation drill (hybrid scheme) --- */
    typedef struct { const char *id; const char *desc; int expected; int got; int pass; } rstep;
    rstep rs[5]; int nrs = 0;
    /* R1: key v1 signs manifest v3, installed v2 -> accept */
    rs[nrs++] = (rstep){"R1", "v1 key signs manifest v3, installed v2", V_OK,
        (policy_check(key_id, NULL, 0, 3, 2, now + 365L * 86400, now) == V_OK &&
         hybrid_verify(mldsa, ml_pk, &ed, (uint8_t *)man, (size_t)manlen, h_ed, ml_sg, ml_sglen) == V_OK) ? V_OK : V_BADSIG, 0};
    /* R2: new key v2 signs manifest v4, installed v3 -> accept */
    ed_key ed2; ed_keygen(&ed2);
    uint8_t *ml2_pk = malloc(mldsa->length_public_key);
    uint8_t *ml2_sk = malloc(mldsa->length_secret_key);
    uint8_t *ml2_sg = malloc(mldsa->length_signature);
    OQS_SIG_keypair(mldsa, ml2_pk, ml2_sk);
    char key_id2[17]; { uint8_t fp[SHA256_DIGEST_LENGTH]; SHA256(ml2_pk, mldsa->length_public_key, fp); hex(fp, 8, key_id2); }
    char man4[1024];
    int man4len = build_manifest(man4, sizeof(man4), "postfiatd-testnet-full-1.0.9.tar.gz",
                                 4, art_hex, key_id2, now + 365L * 86400);
    uint8_t h2_ed[64]; size_t h2_edlen = 64; size_t ml2_sglen = 0;
    ed_sign(&ed2, (uint8_t *)man4, (size_t)man4len, h2_ed, &h2_edlen);
    OQS_SIG_sign(mldsa, ml2_sg, &ml2_sglen, (uint8_t *)man4, (size_t)man4len, ml2_sk);
    rs[nrs++] = (rstep){"R2", "v2 key signs manifest v4, installed v3", V_OK,
        (policy_check(key_id2, NULL, 0, 4, 3, now + 365L * 86400, now) == V_OK &&
         hybrid_verify(mldsa, ml2_pk, &ed2, (uint8_t *)man4, (size_t)man4len, h2_ed, ml2_sg, ml2_sglen) == V_OK) ? V_OK : V_BADSIG, 0};
    /* R3: old v3 manifest under v2 keys -> reject */
    rs[nrs++] = (rstep){"R3", "old v3 manifest verified under v2 keys", V_BADSIG,
        hybrid_verify(mldsa, ml2_pk, &ed2, (uint8_t *)man, (size_t)manlen, h_ed, ml_sg, ml_sglen), 0};
    /* R4: revoke v1 key_id -> v3 manifest rejected at policy */
    rs[nrs++] = (rstep){"R4", "v1 key revoked: v3 manifest rejected", V_REVOKED,
        policy_check(key_id, rev1, 1, 3, 2, now + 365L * 86400, now), 0};
    /* R5: v4 manifest still verifies after v1 revocation */
    rs[nrs++] = (rstep){"R5", "v4 manifest still valid after v1 revocation", V_OK,
        (policy_check(key_id2, rev1, 1, 4, 3, now + 365L * 86400, now) == V_OK &&
         hybrid_verify(mldsa, ml2_pk, &ed2, (uint8_t *)man4, (size_t)man4len, h2_ed, ml2_sg, ml2_sglen) == V_OK) ? V_OK : V_BADSIG, 0};
    for (int i = 0; i < nrs; i++) {
        rs[i].pass = (rs[i].expected == rs[i].got);
        fprintf(stderr, "%s %s: expected=%s got=%s %s\n", rs[i].id, rs[i].desc,
                v_reason(rs[i].expected), v_reason(rs[i].got), rs[i].pass ? "PASS" : "FAIL");
        if (!rs[i].pass) all_ok = 0;
    }

    /* --- JSON output (stdout) --- */
    printf("{\n  \"tool\": \"sign_release (liboqs 0.16.0 + OpenSSL 3.0.13)\",\n");
    printf("  \"artifact\": {\"name\": \"postfiatd-testnet-full-1.0.9.tar.gz\", \"bytes\": %d, \"sha256\": \"%s\", \"hash_us\": %.3f},\n",
           ARTIFACT_BYTES, art_hex, hash_us);
    printf("  \"manifest\": {\"format\": \"PFTL-RELEASE-MANIFEST-v1, fields artifact/version/artifact_sha256/key_id/not_after\", \"version_signed\": 3, \"key_id\": \"%s\"},\n", key_id);
    printf("  \"iterations\": {\"keygen\": %d, \"sign_verify\": %d},\n", KEYGEN_ITERS, SIGN_ITERS);
    printf("  \"schemes\": [\n");
    printf("    {\"name\": \"ed25519\", \"implementation\": \"OpenSSL 3.0.13\", \"pk_bytes\": 32, \"sk_bytes\": 32, \"sig_bytes\": 64, \"keygen_us\": %.3f, \"sign_us\": %.3f, \"verify_us\": %.3f, \"correctness\": \"%s\"},\n",
           ed_kg, ed_sn, ed_vf, ed_ok ? "PASS" : "FAIL");
    for (int i = 0; i < n_oqs; i++)
        printf("    {\"name\": \"%s\", \"implementation\": \"%s\", \"pk_bytes\": %zu, \"sk_bytes\": %zu, \"sig_bytes\": %zu, \"keygen_us\": %.3f, \"sign_us\": %.3f, \"verify_us\": %.3f, \"correctness\": \"%s\"}%s\n",
               r[i].name, r[i].impl, r[i].pk, r[i].sk, r[i].sig,
               r[i].keygen_us, r[i].sign_us, r[i].verify_us,
               r[i].correctness ? "PASS" : "FAIL", i + 1 < n_oqs ? "," : "");
    printf("  ],\n");
    printf("  \"hybrid\": {\"name\": \"hybrid-ed25519-ml-dsa-65\", \"implementation\": \"OpenSSL 3.0.13 + liboqs 0.16.0\", \"sig_bytes\": %zu, \"sign_us\": %.3f, \"verify_us\": %.3f, \"correctness\": \"%s\"},\n",
           (size_t)(64 + ml_sglen), hyb_sn, hyb_vf, hyb_ok ? "PASS" : "FAIL");
    printf("  \"negative_tests\": [\n");
    for (int i = 0; i < nnt; i++)
        printf("    {\"id\": \"%s\", \"description\": \"%s\", \"expected\": \"%s\", \"got\": \"%s\", \"result\": \"%s\"}%s\n",
               nt[i].id, nt[i].desc, v_reason(nt[i].expected), v_reason(nt[i].got),
               nt[i].pass ? "PASS" : "FAIL", i + 1 < nnt ? "," : "");
    printf("  ],\n");
    printf("  \"rotation_drill\": [\n");
    for (int i = 0; i < nrs; i++)
        printf("    {\"id\": \"%s\", \"description\": \"%s\", \"expected\": \"%s\", \"got\": \"%s\", \"result\": \"%s\"}%s\n",
               rs[i].id, rs[i].desc, v_reason(rs[i].expected), v_reason(rs[i].got),
               rs[i].pass ? "PASS" : "FAIL", i + 1 < nrs ? "," : "");
    printf("  ],\n");
    printf("  \"all_checks_pass\": %s\n}\n", all_ok ? "true" : "false");
    fprintf(stderr, "sign_release: all_checks_pass=%s\n", all_ok ? "true" : "false");
    free(artifact);
    return all_ok ? 0 : 1;
}
