# Timing table (median microseconds per operation)

Host: AMD EPYC 9D25 126-Core Processor, 4 cores; Ubuntu 24.04.5 LTS; gcc 13.3.0; liboqs 0.16.0 (minimal build: ML-DSA-65 + SLH-DSA pure 128s/128f SHA2/SHAKE); PQClean commit 0586a824fc0d; OpenSSL OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024).
Each operation is the median of 11 single-shot measurements
(clock_gettime(CLOCK_MONOTONIC)). liboqs runs its x86_64 path;
PQClean is the portable-C `clean` reference. The ratio column
therefore compares an optimized implementation against a
reference, not two equals. Ed25519 is the OpenSSL 3.0.13
classical baseline; the hybrid row is Ed25519 + ML-DSA-65
signed and verified together over one manifest.

| Algorithm | Operation | liboqs median (us) | PQClean median (us) | PQClean / liboqs | OpenSSL median (us) | Hybrid median (us) |
|---|---|---|---|---|---|---|
| ML-DSA-65 | keygen | 47.642 | 269.624 | 5.66 | - | - |
| ML-DSA-65 | sign | 136.475 | 917.155 | 6.72 | - | - |
| ML-DSA-65 | verify | 47.260 | 241.773 | 5.12 | - | - |
| SLH-DSA-SHA2-128s | keygen | 91472.097 | 108510.735 | 1.19 | - | - |
| SLH-DSA-SHA2-128s | sign | 692670.570 | 847707.555 | 1.22 | - | - |
| SLH-DSA-SHA2-128s | verify | 710.776 | 805.448 | 1.13 | - | - |
| SLH-DSA-SHAKE-128s | keygen | 166742.031 | 243960.129 | 1.46 | - | - |
| SLH-DSA-SHAKE-128s | sign | 1282924.657 | 1872710.000 | 1.46 | - | - |
| SLH-DSA-SHAKE-128s | verify | 1177.146 | 1691.808 | 1.44 | - | - |
| SLH-DSA-SHA2-128f | keygen | 1415.873 | 2579.089 | 1.82 | - | - |
| SLH-DSA-SHA2-128f | sign | 33670.295 | 56852.949 | 1.69 | - | - |
| SLH-DSA-SHA2-128f | verify | 2005.969 | 3327.451 | 1.66 | - | - |
| SLH-DSA-SHAKE-128f | keygen | 2653.170 | 3727.792 | 1.41 | - | - |
| SLH-DSA-SHAKE-128f | sign | 62060.040 | 89146.539 | 1.44 | - | - |
| SLH-DSA-SHAKE-128f | verify | 3707.982 | 5410.406 | 1.46 | - | - |
| Ed25519 | keygen | - | - | - | 54.552 | - |
| Ed25519 | sign | - | - | - | 52.839 | - |
| Ed25519 | verify | - | - | - | 140.972 | - |
| hybrid-ed25519-ml-dsa-65 | sign | - | - | - | - | 139.669 |
| hybrid-ed25519-ml-dsa-65 | verify | - | - | - | - | 190.366 |
