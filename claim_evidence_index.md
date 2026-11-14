# Claim-to-evidence index

Every claim in this pack is either **measured** (M: produced by a
runnable script in this pack, with the unedited output shipped) or
**source-derived** (S: read from a primary source — a standard, or the
pinned postfiatd tree — with an exact file:line reference). Open
questions (OQ) are things this pack did **not** verify; they are marked
UNVERIFIED rather than asserted.

Host for all measurements: AMD EPYC 9D25, 4 cores, Ubuntu 24.04.5 LTS,
gcc 13.3.0, liboqs 0.16.0 (minimal build), PQClean commit 0586a824,
OpenSSL 3.0.13. Timings are medians of 11 single-shot measurements
unless stated otherwise. ML-DSA signing uses rejection sampling, so
per-run medians vary; the hybrid medians and the standalone scheme
medians come from separate runs of the same harness, so a hybrid
median need not equal the sum of the standalone medians. Every median
is quoted exactly as the raw logs print it.

## Measured claims (M)

| ID | Claim | Evidence |
|----|-------|----------|
| M-01 | ML-DSA-65 (liboqs): keygen 47.642 us, sign 136.475 us, verify 47.260 us; pk 1,952 B, sk 4,032 B, sig 3,309 B; round-trip PASS | `results/signing_liboqs.json` schemes[1]; `results/raw_sign_liboqs.log` line "ml-dsa-65: ..." |
| M-02 | SLH-DSA-SHA2-128s (liboqs): keygen 91,472.097 us, sign 692,670.570 us, verify 710.776 us; pk 32 B, sk 64 B, sig 7,856 B; round-trip PASS | `results/signing_liboqs.json` schemes[2]; `results/raw_sign_liboqs.log` |
| M-03 | SLH-DSA-SHAKE-128s (liboqs): keygen 166,742.031 us, sign 1,282,924.657 us, verify 1,177.146 us; pk 32 B, sk 64 B, sig 7,856 B; round-trip PASS | `results/signing_liboqs.json` schemes[3]; `results/raw_sign_liboqs.log` |
| M-04 | SLH-DSA-SHA2-128f (liboqs): keygen 1,415.873 us, sign 33,670.295 us, verify 2,005.969 us; pk 32 B, sk 64 B, sig 17,088 B; round-trip PASS | `results/signing_liboqs.json` schemes[4]; `results/raw_sign_liboqs.log` |
| M-05 | SLH-DSA-SHAKE-128f (liboqs): keygen 2,653.170 us, sign 62,060.040 us, verify 3,707.982 us; pk 32 B, sk 64 B, sig 17,088 B; round-trip PASS | `results/signing_liboqs.json` schemes[5]; `results/raw_sign_liboqs.log` |
| M-06 | Ed25519 (OpenSSL 3.0.13): keygen 54.552 us, sign 52.839 us, verify 140.972 us; pk 32 B, sk 32 B, sig 64 B; round-trip PASS | `results/signing_liboqs.json` schemes[0]; `results/raw_sign_liboqs.log` line "ed25519: ..." |
| M-07 | Hybrid Ed25519 + ML-DSA-65: signature 3,373 bytes (64 + 3,309); sign 139.669 us, verify 190.366 us; round-trip PASS | `results/signing_liboqs.json` hybrid; `results/raw_sign_liboqs.log` line "hybrid ed25519+ml-dsa-65: ..." |
| M-08 | ML-DSA-65 (PQClean clean): keygen 269.624 us, sign 917.155 us, verify 241.773 us; sizes identical to M-01; round-trip PASS, tampered signature rejected | `results/signing_pqclean_mldsa65.json`; `results/raw_sign_pqclean_mldsa65.log` |
| M-09 | SLH-DSA-SHA2-128s (PQClean clean): keygen 108,510.735 us, sign 847,707.555 us, verify 805.448 us; sizes identical to M-02; round-trip PASS, tampered signature rejected | `results/signing_pqclean_sphincs_sha2_128s.json`; `results/raw_sign_pqclean_sphincs_sha2_128s.log` |
| M-10 | SLH-DSA-SHAKE-128s (PQClean clean): keygen 243,960.129 us, sign 1,872,710.000 us, verify 1,691.808 us; sizes identical to M-03; round-trip PASS, tampered signature rejected | `results/signing_pqclean_sphincs_shake_128s.json`; `results/raw_sign_pqclean_sphincs_shake_128s.log` |
| M-11 | SLH-DSA-SHA2-128f (PQClean clean): keygen 2,579.089 us, sign 56,852.949 us, verify 3,327.451 us; sizes identical to M-04; round-trip PASS, tampered signature rejected | `results/signing_pqclean_sphincs_sha2_128f.json`; `results/raw_sign_pqclean_sphincs_sha2_128f.log` |
| M-12 | SLH-DSA-SHAKE-128f (PQClean clean): keygen 3,727.792 us, sign 89,146.539 us, verify 5,410.406 us; sizes identical to M-05; round-trip PASS, tampered signature rejected | `results/signing_pqclean_sphincs_shake_128f.json`; `results/raw_sign_pqclean_sphincs_shake_128f.log` |
| M-13 | All 10 measured size rows match the FIPS tables (verdict MATCH) | `results/size_table.md`; `build_derived.py` size gate (exit 0) |
| M-14 | Negative tests 12/12 PASS: tampered manifest (N1, N10), tampered ML-DSA-65 signature (N2), tampered Ed25519 signature (N3), wrong public key (N4, N12), rollback version 2 vs installed 3 (N5), revoked key (N6), expired key (N7), clean-manifest control (N8), SLH-DSA-SHA2-128s control (N9), tampered SLH-DSA signature (N11) | `results/signing_liboqs.json` negative_tests; `results/raw_sign_liboqs.log` lines "N1 ..." through "N12 ..." |
| M-15 | Rotation drill 5/5 PASS: R1 v1 signs v3, R2 v2 signs v4, R3 old manifest fails under v2 keys, R4 v1 revocation blocks old manifest, R5 new manifest unaffected | `results/signing_liboqs.json` rotation_drill; `results/raw_sign_liboqs.log` lines "R1 ..." through "R5 ..." |
| M-16 | Test artifact: deterministic 1 MiB payload, SHA-256 fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83, hash time 2,711.077 us | `results/signing_liboqs.json` artifact; `results/raw_sign_liboqs.log` line "artifact: ..." |
| M-17 | Cross-implementation agreement: same scheme, same sizes in both implementations (all 5 schemes); timing ratios PQClean:liboqs 5.12x–6.72x for ML-DSA-65, 1.13x–1.82x for SLH-DSA (reference C vs optimized liboqs) | `results/timing_table.md` ratio column; `results/size_table.md` |
| M-18 | The stock liboqs 0.16.0 install used by the sibling lattice pack has SLH-DSA disabled (all OQS_ENABLE_SIG_slh_dsa_* undefined in its oqsconfig.h; nm finds no slh_dsa symbols in its liboqs.a). This pack rebuilt liboqs 0.16.0 from the same sources with OQS_MINIMAL_BUILD for ML-DSA-65 + SLH-DSA pure 128s/128f; OQS_SIG_new succeeds for all five schemes and sizes match the FIPS tables | `sources.md`; `harness/build_signing.sh` (liboqs-slh-install); `results/raw_sign_liboqs.log` (all five schemes PASS) |
| M-19 | Hybrid verify 190.366 us vs SLH-DSA-SHA2-128s verify 710.776 us (3.73x); hybrid sign 139.669 us vs SLH-DSA-SHA2-128s sign 692,670.570 us (4,959.4x); hybrid signature 3,373 B vs 7,856 B (2.33x) and 17,088 B (5.07x); hybrid keygen 102.194 us vs SLH-DSA-128s keygen 91,472.097 us (895.1x) — all liboqs medians | `results/cost_model.json` ratios_vs_hybrid; `results/summary.txt` |
| M-20 | Pack reproduces from a fresh copy: `bash run_all.sh` exit 0, `bash verify_digests.sh --check` exit 0, all derived outputs byte-identical (fresh-copy run leaves a clean tree) | `results/run_log.txt`; `results/digest_check_output.txt`; `REPRODUCTION.md` |

## Source-derived claims (S)

| ID | Claim | Evidence (primary source) |
|----|-------|---------------------------|
| S-01 | ML-DSA-65: secret key 4,032 B, public key 1,952 B, signature 3,309 B, category 3 | FIPS 204 Table 2 ("Sizes (in bytes) of keys and signatures of ML-DSA", p. 16) (`sources/NIST.FIPS.204.pdf`) |
| S-02 | SLH-DSA-SHA2-128s / SLH-DSA-SHAKE-128s: n=16, h=63, d=7, h'=9, a=12, k=14, lgw=4, m=30, category 1, public key 32 B, signature 7,856 B | FIPS 205 Table 2 (`sources/NIST.FIPS.205.pdf`, p. 43) |
| S-03 | SLH-DSA-SHA2-128f / SLH-DSA-SHAKE-128f: n=16, h=66, d=22, h'=3, a=6, k=33, lgw=4, m=34, category 1, public key 32 B, signature 17,088 B | FIPS 205 Table 2 (`sources/NIST.FIPS.205.pdf`, p. 43) |
| S-04 | SLH-DSA private key is 4n bytes and public key 2n bytes (64 B / 32 B for n=16) | FIPS 205 section 3.2, "Key checks" (`sources/NIST.FIPS.205.pdf`) |
| S-05 | SLH-DSA is based on SPHINCS+, selected for standardisation in the NIST PQC process; the PQClean "simple" variants implement the FIPS 205 parameter sets (SPX_N=16, SPX_FULL_HEIGHT=63, SPX_D=7 for 128s) | FIPS 205 Foreword; PQClean `crypto_sign/sphincs-shake-128s-simple/clean/params.h` |
| S-06 | postfiatd has no release-artifact signing: the release process is version-string + Docker tags + GitHub Release, with no artifact signatures or checksums anywhere in the process description | postfiatd `docs/RELEASE.md:5-28` (version source, release creation, "Do not create the v{version} tag or the release by hand"); `src/libxrpl/protocol/BuildInfo.cpp:39` (versionString "1.0.9") |
| S-07 | Validator manifest rotation design: when an ephemeral key is compromised, a new signing key pair is created with a new manifest at a higher sequence number, signed by the master key; peers verify with the master key and discard the old ephemeral key; a master-key compromise is answered by a revocation manifest with sequence number 0xFFFFFFFF, after which no further manifests for that master key are accepted | postfiatd `src/xrpld/app/misc/Manifest.h:66-77`; `src/xrpld/app/misc/detail/Manifest.cpp:196-230` (`Manifest::verify`), `:120-156` (revocation handling), `:43` (`revoked()`) |
| S-08 | Transaction signing supports Ed25519 (64-byte signatures) and secp256k1 (SHA-512-half digest + ECDSA DER); digest signing is secp256k1-only | postfiatd `src/libxrpl/protocol/SecretKey.cpp:230-250` (`signDigest`), `:260-276` (`sign`, Ed25519 branch `:263-265`); `src/libxrpl/protocol/Sign.cpp:34` (`sign`), `:48` (`verify`) |
| S-09 | Validation signatures are verified with `verifyDigest` (secp256k1-only gate: `publicKeyType(getSignerPublic()) == KeyType::secp256k1`) | postfiatd `src/libxrpl/protocol/STValidation.cpp:125-141`; `verifyDigest` defined in `src/libxrpl/protocol/PublicKey.cpp:239` |
| S-10 | A signed JSON list already exists in-tree as a pattern: `scripts/sign_exclusion_list.py` signs an exclusion-list JSON with NaCl Ed25519 for `RemoteExclusionListFetcher` verification | postfiatd `scripts/sign_exclusion_list.py:1-14` |
| S-11 | postfiatd pins OpenSSL 1.1.1w (no native ML-KEM/ML-DSA; those arrived in OpenSSL 3.5), so any PQC signing in postfiatd needs liboqs or equivalent, not the pinned OpenSSL | postfiatd `conanfile.py:30` |
| S-12 | Release versions are immutable and overwrite-protected by Docker Hub tag checks ("fails if the version already exists"); releases are the public announcement feed (GitHub Releases atom feed) | postfiatd `docs/RELEASE.md:31-50` (image tags, overwrite protection) |
| S-13 | FIPS 204 and FIPS 205 were both published 13 August 2024 | Title pages of `sources/NIST.FIPS.204.pdf` and `sources/NIST.FIPS.205.pdf` |

## Open questions (UNVERIFIED)

| ID | Question | Status |
|----|----------|--------|
| OQ-1 | OpenSSL 3.5 (native ML-DSA/SLH-DSA) timings on this host | UNVERIFIED — system OpenSSL is 3.0.13; not measured |
| OQ-2 | Optimized (AVX2) SLH-DSA implementations on this host | UNVERIFIED — only reference-C (PQClean clean) and liboqs x86_64 measured; optimized builds would be faster |
| OQ-3 | Production release signing in postfiatd | UNVERIFIED — no such code exists in the pinned tree (see S-06); the manifest format and design in `release_signing_assessment.md` are a proposal, not a deployed format |
| OQ-4 | Timings on real validator/release hardware | UNVERIFIED — this host is a shared virtual CPU; ratios are the portable part |
| OQ-5 | ML-DSA-44 / ML-DSA-87 for release signing | UNVERIFIED — only ML-DSA-65 measured here |
| OQ-6 | SLH-DSA-192s/256s parameter sets | UNVERIFIED — only the 128s/128f sets measured here |
| OQ-7 | The actual number of PFTL operators/verifiers who would verify a release | UNVERIFIED — cost-model fleet sizes (100 / 1,000 / 10,000) are assumptions, labelled as such |
