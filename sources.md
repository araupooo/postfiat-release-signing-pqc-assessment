# Primary sources

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA),
  published 13 August 2024. DOI 10.6028/NIST.FIPS.204.
  Vendored: `sources/NIST.FIPS.204.pdf` (3,291,746 bytes,
  SHA-256 57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b).
  Size table used: Table 2 (ML-DSA-65: secret key 4,032 bytes, public key
  1,952 bytes, signature 3,309 bytes, category 3).
- NIST FIPS 205, Stateless Hash-Based Digital Signature Standard (SLH-DSA),
  published 13 August 2024. DOI 10.6028/NIST.FIPS.205.
  Vendored: `sources/NIST.FIPS.205.pdf` (1,055,752 bytes,
  SHA-256 8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d).
  Size table used: Table 2 (SLH-DSA-SHA2-128s / SLH-DSA-SHAKE-128s:
  n=16, h=63, d=7, h'=9, a=12, k=14, lgw=4, m=30, category 1, public key
  32 bytes, signature 7,856 bytes; SLH-DSA-SHA2-128f / SLH-DSA-SHAKE-128f:
  n=16, h=66, d=22, h'=3, a=6, k=33, lgw=4, m=34, category 1, public key
  32 bytes, signature 17,088 bytes). Private-key length 4n bytes and
  public-key length 2n bytes per FIPS 205 section 3.2 ("Key checks").
- liboqs 0.16.0 (Open Quantum Safe), minimal build: ML-DSA-65 and
  SLH-DSA pure 128s/128f (SHA2 and SHAKE). The stock 0.16.0 install used
  for the earlier lattice pack has SLH-DSA disabled (all
  OQS_ENABLE_SIG_slh_dsa_* undefined in its oqsconfig.h, confirmed by
  nm: no slh_dsa symbols in its liboqs.a), so liboqs was rebuilt from
  the same 0.16.0 sources with OQS_MINIMAL_BUILD for the five schemes
  used here. Verification: OQS_SIG_new succeeds for all five and the
  measured sizes match the FIPS tables exactly.
- PQClean, commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f (2026-08-04),
  "clean" reference implementations: crypto_sign/ml-dsa-65 (from the
  pinned checkout) and crypto_sign/sphincs-{shake,sha2}-{128s,128f}-simple
  (fetched from the same commit; the "simple" variants are the FIPS 205
  parameter sets — SPX_N=16, SPX_FULL_HEIGHT=63, SPX_D=7 for 128s,
  confirmed in params.h). SPHINCS+ is the algorithm SLH-DSA was
  standardised from (FIPS 205 Foreword).
- OpenSSL 3.0.13 (system), for the Ed25519 classical baseline.
  OpenSSL 3.0.13 has no native ML-DSA or SLH-DSA (added in OpenSSL 3.5),
  so it is used only for Ed25519 here.
- postfiatd, pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55
  (upstream XRPL rippled 2.5.0 with postfiatd hardening). Call-site
  mapping in `call_sites.md` cites exact files and lines in that tree.

All PDFs were downloaded from nvlpubs.nist.gov (NIST Publications) on
2026-11-14 and verified by title page and SHA-256. The FIPS 204 copy is
byte-identical to the copy vendored in the sibling lattice pack
(SHA-256 57239b9f...).
