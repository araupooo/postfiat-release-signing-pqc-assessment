#!/bin/bash
# Build the signing drivers from pinned sources.
# Usage: bash harness/build_signing.sh [liboqs-install-dir] [pqclean-slh-dir] [pqclean-checkout-dir]
# Defaults: liboqs at ../build/liboqs-slh-install (minimal build: ML-DSA-65 +
# SLH-DSA pure 128s/128f, SHA2 + SHAKE), PQClean SLH-DSA sources at
# ../build/pqclean-slh (fetched at pinned commit 0586a824), PQClean ML-DSA
# sources at ../../task-633f.../pqclean-checkout (same pinned commit).
# Outputs binaries into ../build/bin (relative to the task dir, NOT the pack).
# Exit 0 only if all 6 binaries build.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TASKDIR="$(cd "$HERE/../.." && pwd)"
OQS="${1:-$TASKDIR/build/liboqs-slh-install}"
SLH="${2:-$TASKDIR/build/pqclean-slh}"
PQ="${3:-$TASKDIR/../task-633f3fb9d53133dfbc8c22db7c25ecc7/pqclean-checkout}"
OUT="${OUT:-$TASKDIR/build/bin}"
mkdir -p "$OUT"
COMMIT="0586a824fc0d49df0b6b6e9179d8d15d06d0974f"

fail=0
echo "liboqs install: $OQS"
echo "pqclean slh dir: $SLH"
echo "pqclean checkout: $PQ"
echo "output dir: $OUT"

# --- liboqs + OpenSSL driver (hybrid, ML-DSA, SLH-DSA, Ed25519) ---
if [ -f "$OQS/include/oqs/oqs.h" ] && [ -f "$OQS/lib/liboqs.a" ]; then
  gcc -O2 -std=c99 -Wall -I"$OQS/include" -o "$OUT/sign_release" \
    "$HERE/sign_release.c" -L"$OQS/lib" -loqs -lcrypto
  echo "built: sign_release (exit $?)"
else
  echo "SKIP sign_release: liboqs install not found at $OQS" >&2
  fail=1
fi

# --- PQClean drivers (one binary per parameter set) ---
COMMON="$SLH/common"
build_pqclean() { # $1=dir $2=prefix $3=outname $4...=sources
  local dir="$1" prefix="$2" out="$3"; shift 3
  # shellcheck disable=SC2086
  gcc -O2 -std=c99 -Wall -I"$dir" -I"$COMMON" -DPQ_SIG \
    -DPREFIX="$prefix" -DPQCLEAN_COMMIT="\"$COMMIT\"" \
    -o "$OUT/$out" "$HERE/sign_pqclean.c" "$@" \
    "$COMMON/fips202.c" "$COMMON/sha2.c" "$COMMON/randombytes.c"
  echo "built: $out (exit $?)"
}

MLDSA_SRC="sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c symmetric-shake.c"
D="$PQ/crypto_sign/ml-dsa-65/clean"
# shellcheck disable=SC2086
build_pqclean "$D" "PQCLEAN_MLDSA65_CLEAN" "sign_pqclean_mldsa65" \
  $(for f in $MLDSA_SRC; do echo "$D/$f"; done)

for SCHEME in shake-128s shake-128f sha2-128s sha2-128f; do
  case "$SCHEME" in
    shake-128s) DIR="sphincs-shake-128s-simple"; PRE="PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN"; OUTNAME="sign_pqclean_sphincs_shake_128s"; SRC="address.c context_shake.c fors.c hash_shake.c merkle.c sign.c thash_shake_simple.c utils.c utilsx1.c wots.c wotsx1.c" ;;
    shake-128f) DIR="sphincs-shake-128f-simple"; PRE="PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN"; OUTNAME="sign_pqclean_sphincs_shake_128f"; SRC="address.c context_shake.c fors.c hash_shake.c merkle.c sign.c thash_shake_simple.c utils.c utilsx1.c wots.c wotsx1.c" ;;
    sha2-128s) DIR="sphincs-sha2-128s-simple"; PRE="PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN"; OUTNAME="sign_pqclean_sphincs_sha2_128s"; SRC="address.c context_sha2.c fors.c hash_sha2.c merkle.c sign.c thash_sha2_simple.c utils.c utilsx1.c wots.c wotsx1.c" ;;
    sha2-128f) DIR="sphincs-sha2-128f-simple"; PRE="PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN"; OUTNAME="sign_pqclean_sphincs_sha2_128f"; SRC="address.c context_sha2.c fors.c hash_sha2.c merkle.c sign.c thash_sha2_simple.c utils.c utilsx1.c wots.c wotsx1.c" ;;
  esac
  D="$SLH/crypto_sign/$DIR/clean"
  # shellcheck disable=SC2086
  build_pqclean "$D" "$PRE" "$OUTNAME" $(for f in $SRC; do echo "$D/$f"; done)
done

for b in sign_release sign_pqclean_mldsa65 sign_pqclean_sphincs_shake_128s sign_pqclean_sphincs_shake_128f sign_pqclean_sphincs_sha2_128s sign_pqclean_sphincs_sha2_128f; do
  if [ -x "$OUT/$b" ]; then echo "OK   $b"; else echo "FAIL $b"; fail=1; fi
done
exit $fail
