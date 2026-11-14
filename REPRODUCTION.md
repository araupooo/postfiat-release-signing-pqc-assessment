# Reproduction

## Offline reproduction (derived outputs only)

```sh
bash run_all.sh
```

Expected: exit 0. Output ends with:

```
build_derived.py: OK (timing/size/cost tables, summary, docs/index.html)
...
verify_digests.sh: SHA256SUMS regenerated and verified
run_all.sh: OK
```

and `bash verify_digests.sh --check` exits 0 with every file OK.
All derived outputs are byte-identical to the shipped files; a
fresh-copy run leaves no modified files behind.

## Re-running the signing measurements

Timings vary run to run and are NOT part of the offline reproduction.
To re-measure:

```sh
bash harness/build_signing.sh   # builds 6 drivers into ../build/bin
bash harness/run_signing.sh     # runs them, writes results/signing_*.json
bash run_all.sh                 # re-derive the tables from the new JSON
```

Prerequisites (see `sources.md` for pins):

- liboqs 0.16.0 minimal build with ML-DSA-65 and SLH-DSA pure 128s/128f
  (SHA2 and SHAKE) enabled, installed at `../build/liboqs-slh-install`.
  The stock 0.16.0 install used for the earlier lattice pack has
  SLH-DSA disabled, so it cannot be reused for SLH-DSA. Rebuild with:
  `cmake -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_shake_128s;SIG_slh_dsa_pure_sha2_128f;SIG_slh_dsa_pure_shake_128f"`.
- PQClean at commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f:
  `crypto_sign/ml-dsa-65/clean` and
  `crypto_sign/sphincs-{shake,sha2}-{128s,128f}-simple/clean`, plus
  `common/{fips202,sha2,randombytes,compat}.{c,h}`.
- gcc 13.3.0, OpenSSL 3.0.13 (Ed25519 only), Python 3.12.3.
- No network is needed at run time: all inputs are vendored.

## Recorded reproduction result

(The fresh-copy run log is shipped as `results/run_log.txt`; the
digest-check output as `results/digest_check_output.txt`. Both are
embedded inline in `docs/index.html`.)
