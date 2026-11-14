# Size table (bytes)

FIPS 204 Table 2 (ML-DSA-65) and FIPS 205 Table 2 (SLH-DSA), both
published 13 August 2024; SLH-DSA private-key length 4n bytes and
public-key length 2n bytes per FIPS 205 section 3.2. Every measured
size in this pack matches the standard's table for its parameter
set; the verdict column is the check, not a claim.

| Algorithm | Implementation | Category | pk | sk | sig | FIPS pk | FIPS sk | FIPS sig | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-65 | liboqs | 3 | 1952 | 4032 | 3309 | 1952 | 4032 | 3309 | MATCH |
| ML-DSA-65 | pqclean | 3 | 1952 | 4032 | 3309 | 1952 | 4032 | 3309 | MATCH |
| SLH-DSA-SHA2-128s | liboqs | 1 | 32 | 64 | 7856 | 32 | 64 | 7856 | MATCH |
| SLH-DSA-SHA2-128s | pqclean | 1 | 32 | 64 | 7856 | 32 | 64 | 7856 | MATCH |
| SLH-DSA-SHAKE-128s | liboqs | 1 | 32 | 64 | 7856 | 32 | 64 | 7856 | MATCH |
| SLH-DSA-SHAKE-128s | pqclean | 1 | 32 | 64 | 7856 | 32 | 64 | 7856 | MATCH |
| SLH-DSA-SHA2-128f | liboqs | 1 | 32 | 64 | 17088 | 32 | 64 | 17088 | MATCH |
| SLH-DSA-SHA2-128f | pqclean | 1 | 32 | 64 | 17088 | 32 | 64 | 17088 | MATCH |
| SLH-DSA-SHAKE-128f | liboqs | 1 | 32 | 64 | 17088 | 32 | 64 | 17088 | MATCH |
| SLH-DSA-SHAKE-128f | pqclean | 1 | 32 | 64 | 17088 | 32 | 64 | 17088 | MATCH |

Classical and hybrid, measured on the same host:

| Scheme | pk | sk | sig |
|---|---|---|---|
| Ed25519 (OpenSSL 3.0.13) | 32 | 32 | 64 |
| Hybrid Ed25519 + ML-DSA-65 | 32 + 1,952 = 1,984 | 32 + 4,032 = 4,064 | 64 + 3,309 = 3,373 |
