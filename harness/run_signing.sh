#!/bin/bash
# Run every signing driver and collect JSON results + raw logs.
# Usage: bash harness/run_signing.sh
# Binaries are expected in ../build/bin (see harness/build_signing.sh).
# Outputs (relative to the pack root): results/signing_liboqs.json,
# results/signing_pqclean_*.json, results/raw_sign_*.log, results/environment.json.
# Exit 0 only if every driver exits 0 (all correctness checks pass).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PACKDIR="$(cd "$HERE/.." && pwd)"
TASKDIR="$(cd "$PACKDIR/.." && pwd)"
BIN="$TASKDIR/build/bin"
RES="$PACKDIR/results"
mkdir -p "$RES"

# NOTE: PQClean drivers print the --json path they were given into
# their raw log. Pass a RELATIVE path (from the pack root) so no
# local directory name leaks into the shipped logs.
cd "$PACKDIR"

fail=0
run() { # $1=label $2...=command (stdout->json or log, stderr->log)
  local label="$1"; shift
  echo "=== $label ==="
  "$@" ; local rc=$?
  echo "exit: $rc"
  [ "$rc" -ne 0 ] && fail=1
  return $rc
}

# --- environment record ---
{
  echo "{"
  echo "  \"cpu\": \"$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)\","
  echo "  \"cores\": $(nproc),"
  echo "  \"os\": \"$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')\","
  echo "  \"gcc\": \"$(gcc --version | head -1)\","
  echo "  \"cmake\": \"$(cmake --version | head -1)\","
  echo "  \"python\": \"$(python3 --version)\","
  echo "  \"openssl\": \"$(openssl version)\","
  echo "  \"liboqs\": \"0.16.0 (minimal build: ML-DSA-65 + SLH-DSA pure 128s/128f SHA2/SHAKE)\","
  echo "  \"pqclean_commit\": \"0586a824fc0d49df0b6b6e9179d8d15d06d0974f\","
  echo "  \"postfiatd_pinned_commit\": \"0085a1ff885d6a446369cf73a4430f75af22be55\""
  echo "}"
} > "$RES/environment.json"
echo "wrote results/environment.json"

# --- liboqs + OpenSSL driver: JSON to stdout, log to stderr ---
"$BIN/sign_release" > "$RES/signing_liboqs.json" 2> "$RES/raw_sign_liboqs.log"
rc=$?; echo "sign_release exit: $rc"; [ "$rc" -ne 0 ] && fail=1

# --- PQClean drivers: one JSON + one raw log per scheme ---
for spec in "mldsa65:ML-DSA-65" "sphincs_shake_128s:SLH-DSA-SHAKE-128s" "sphincs_shake_128f:SLH-DSA-SHAKE-128f" "sphincs_sha2_128s:SLH-DSA-SHA2-128s" "sphincs_sha2_128f:SLH-DSA-SHA2-128f"; do
  bin="${spec%%:*}"
  "$BIN/sign_pqclean_$bin" --json "results/signing_pqclean_$bin.json" > "$RES/raw_sign_pqclean_$bin.log" 2>&1
  rc=$?; echo "sign_pqclean_$bin exit: $rc"; [ "$rc" -ne 0 ] && fail=1
done

echo "run_signing.sh: $([ $fail -eq 0 ] && echo OK || echo FAIL)"
exit $fail
