#!/usr/bin/env python3
"""Build derived outputs from the vendored signing results.

Reads results/signing_liboqs.json, results/signing_pqclean_*.json and
results/environment.json (vendored inputs: raw outputs of the signing
drivers, shipped in this pack) and writes, deterministically (no
timestamps, fixed float formatting):

  results/timing_table.csv / timing_table.md — median us/op per scheme,
      operation and implementation, with the PQClean:liboqs ratio.
  results/size_table.csv / size_table.md — measured key/signature sizes
      against the FIPS 204 Table 2 / FIPS 205 Table 2 values, with a
      match/mismatch verdict per cell.
  results/cost_model.json / cost_model.csv — per-release and per-verifier
      costs (CPU and signature bytes) computed from the MEASURED medians
      under stated fleet sizes. These are DERIVED arithmetic, not new
      measurements.
  results/summary.txt — headline numbers in plain text.
  docs/index.html — rendered results page, including the digest-check
      output (results/digest_check_output.txt, if present) and the
      tail of the run log (results/run_log.txt, if present) inline.

Usage: python3 build_derived.py
Exit 0 only if every size in the JSON matches the FIPS tables, every
correctness field is PASS, every negative test is PASS and every
rotation-drill step is PASS. A mismatch is printed and exits 1 —
sizes are never silently "fixed".
"""
import csv
import html
import json
import os
import sys

PACK = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(PACK, "results")

# FIPS 204, Table 2 (sizes in bytes), published 13 Aug 2024.
FIPS204 = {
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309, "category": 3},
}
# FIPS 205, Table 2 (sizes in bytes), published 13 Aug 2024.
# Private key 4n bytes, public key 2n bytes (FIPS 205 section 3.2).
FIPS205 = {
    "SLH-DSA-SHA2-128s": {"pk": 32, "sk": 64, "sig": 7856, "category": 1,
                          "n": 16, "h": 63, "d": 7, "hp": 9, "a": 12, "k": 14,
                          "lgw": 4, "m": 30},
    "SLH-DSA-SHAKE-128s": {"pk": 32, "sk": 64, "sig": 7856, "category": 1,
                           "n": 16, "h": 63, "d": 7, "hp": 9, "a": 12, "k": 14,
                           "lgw": 4, "m": 30},
    "SLH-DSA-SHA2-128f": {"pk": 32, "sk": 64, "sig": 17088, "category": 1,
                          "n": 16, "h": 66, "d": 22, "hp": 3, "a": 6, "k": 33,
                          "lgw": 4, "m": 34},
    "SLH-DSA-SHAKE-128f": {"pk": 32, "sk": 64, "sig": 17088, "category": 1,
                           "n": 16, "h": 66, "d": 22, "hp": 3, "a": 6, "k": 33,
                           "lgw": 4, "m": 34},
}
FIPS = dict(FIPS204)
FIPS.update(FIPS205)

LIBOQS_NAMES = {
    "ml-dsa-65": "ML-DSA-65",
    "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s",
    "slh-dsa-shake-128s": "SLH-DSA-SHAKE-128s",
    "slh-dsa-sha2-128f": "SLH-DSA-SHA2-128f",
    "slh-dsa-shake-128f": "SLH-DSA-SHAKE-128f",
}
PQCLEAN_NAMES = {
    "ML-DSA-65": "ML-DSA-65",
    "SPHINCS+-sha2-128s-simple": "SLH-DSA-SHA2-128s",
    "SPHINCS+-shake-128s-simple": "SLH-DSA-SHAKE-128s",
    "SPHINCS+-sha2-128f-simple": "SLH-DSA-SHA2-128f",
    "SPHINCS+-shake-128f-simple": "SLH-DSA-SHAKE-128f",
}
SCHEME_ORDER = ["ML-DSA-65", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",
                "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"]
OPS = ["keygen", "sign", "verify"]


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as fh:
        return json.load(fh)


def main():
    liboqs = load("signing_liboqs.json")
    env = load("environment.json")
    pqclean = {}
    for suffix in ("mldsa65", "sphincs_shake_128s", "sphincs_shake_128f",
                   "sphincs_sha2_128s", "sphincs_sha2_128f"):
        pqclean[suffix] = load("signing_pqclean_%s.json" % suffix)

    # by_scheme[scheme][impl] = {pk, sk, sig, keygen_us, sign_us, verify_us, correctness}
    by_scheme = {}
    for s in liboqs["schemes"]:
        if s["name"] == "ed25519":
            by_scheme.setdefault("Ed25519", {})["openssl"] = {
                "pk_bytes": s["pk_bytes"], "sk_bytes": s["sk_bytes"],
                "sig_bytes": s["sig_bytes"], "keygen_us": s["keygen_us"],
                "sign_us": s["sign_us"], "verify_us": s["verify_us"],
                "correctness": s["correctness"]}
            continue
        name = LIBOQS_NAMES[s["name"]]
        by_scheme.setdefault(name, {})["liboqs"] = {
            "pk_bytes": s["pk_bytes"], "sk_bytes": s["sk_bytes"],
            "sig_bytes": s["sig_bytes"], "keygen_us": s["keygen_us"],
            "sign_us": s["sign_us"], "verify_us": s["verify_us"],
            "correctness": s["correctness"]}
    for doc in pqclean.values():
        r = doc["results"][0]
        name = PQCLEAN_NAMES[r["algorithm"]]
        by_scheme.setdefault(name, {})["pqclean"] = {
            "pk_bytes": r["pk_bytes"], "sk_bytes": r["sk_bytes"],
            "sig_bytes": r["sig_bytes"],
            "keygen_us": r["keygen_us"]["median"],
            "sign_us": r["sign_us"]["median"],
            "verify_us": r["verify_us"]["median"],
            "correctness": r["correctness"]}
    ed = by_scheme["Ed25519"]["openssl"]

    errors = []
    # --- correctness gate ---
    for alg, impls in sorted(by_scheme.items()):
        for impl, r in sorted(impls.items()):
            if r.get("correctness") != "PASS":
                errors.append("%s (%s): correctness=%s" % (alg, impl, r.get("correctness")))
    if liboqs.get("all_checks_pass") is not True:
        errors.append("signing_liboqs.json: all_checks_pass is not true")
    for t in liboqs["negative_tests"]:
        if t["result"] != "PASS":
            errors.append("negative test %s: %s" % (t["id"], t["result"]))
    for t in liboqs["rotation_drill"]:
        if t["result"] != "PASS":
            errors.append("rotation drill %s: %s" % (t["id"], t["result"]))

    # --- size gate against FIPS tables ---
    size_rows = []
    for alg in SCHEME_ORDER:
        f = FIPS[alg]
        for impl in ("liboqs", "pqclean"):
            r = by_scheme[alg][impl]
            row = {"algorithm": alg, "implementation": impl,
                   "pk_bytes": r["pk_bytes"], "sk_bytes": r["sk_bytes"],
                   "sig_bytes": r["sig_bytes"],
                   "fips_pk": f["pk"], "fips_sk": f["sk"], "fips_sig": f["sig"],
                   "category": f["category"]}
            row["verdict"] = ("MATCH" if (r["pk_bytes"] == f["pk"] and r["sk_bytes"] == f["sk"]
                                          and r["sig_bytes"] == f["sig"]) else "MISMATCH")
            if row["verdict"] != "MATCH":
                errors.append("%s (%s): size mismatch vs FIPS table" % (alg, impl))
            size_rows.append(row)

    if errors:
        for e in errors:
            print("ERROR: %s" % e, file=sys.stderr)
        return 1

    # --- timing table ---
    timing_rows = []
    for alg in SCHEME_ORDER:
        for op in OPS:
            lq = by_scheme[alg]["liboqs"]
            pq = by_scheme[alg]["pqclean"]
            timing_rows.append({"algorithm": alg, "operation": op,
                                "liboqs_median_us": lq["%s_us" % op],
                                "pqclean_median_us": pq["%s_us" % op],
                                "pqclean_over_liboqs": pq["%s_us" % op] / lq["%s_us" % op]})
    for op in OPS:
        timing_rows.append({"algorithm": "Ed25519", "operation": op,
                            "liboqs_median_us": "", "pqclean_median_us": "",
                            "pqclean_over_liboqs": "",
                            "openssl_median_us": ed["%s_us" % op]})
    hyb = liboqs["hybrid"]
    for op in ("sign", "verify"):
        timing_rows.append({"algorithm": "hybrid-ed25519-ml-dsa-65", "operation": op,
                            "liboqs_median_us": "", "pqclean_median_us": "",
                            "pqclean_over_liboqs": "",
                            "openssl_median_us": "",
                            "hybrid_median_us": hyb["%s_us" % op]})

    with open(os.path.join(RES, "timing_table.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["algorithm", "operation", "liboqs_median_us", "pqclean_median_us",
                    "pqclean_over_liboqs", "openssl_median_us", "hybrid_median_us"])
        for r in timing_rows:
            w.writerow([r["algorithm"], r["operation"],
                        ("%.3f" % r["liboqs_median_us"]) if r["liboqs_median_us"] != "" else "",
                        ("%.3f" % r["pqclean_median_us"]) if r["pqclean_median_us"] != "" else "",
                        ("%.2f" % r["pqclean_over_liboqs"]) if r["pqclean_over_liboqs"] != "" else "",
                        ("%.3f" % r["openssl_median_us"]) if r.get("openssl_median_us", "") != "" else "",
                        ("%.3f" % r["hybrid_median_us"]) if r.get("hybrid_median_us", "") != "" else ""])

    def f3(x):
        return ("%.3f" % x) if isinstance(x, float) else str(x)

    md = ["# Timing table (median microseconds per operation)",
          "",
          "Host: %s, %d cores; %s; gcc %s; liboqs %s; PQClean commit %s; OpenSSL %s."
          % (env["cpu"], env["cores"], env["os"], env["gcc"].split()[-1],
             env["liboqs"], env["pqclean_commit"][:12], env["openssl"]),
          "Each operation is the median of 11 single-shot measurements",
          "(clock_gettime(CLOCK_MONOTONIC)). liboqs runs its x86_64 path;",
          "PQClean is the portable-C `clean` reference. The ratio column",
          "therefore compares an optimized implementation against a",
          "reference, not two equals. Ed25519 is the OpenSSL 3.0.13",
          "classical baseline; the hybrid row is Ed25519 + ML-DSA-65",
          "signed and verified together over one manifest.",
          "",
          "| Algorithm | Operation | liboqs median (us) | PQClean median (us) | PQClean / liboqs | OpenSSL median (us) | Hybrid median (us) |",
          "|---|---|---|---|---|---|---|"]
    for r in timing_rows:
        md.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            r["algorithm"], r["operation"],
            f3(r["liboqs_median_us"]) if r["liboqs_median_us"] != "" else "-",
            f3(r["pqclean_median_us"]) if r["pqclean_median_us"] != "" else "-",
            ("%.2f" % r["pqclean_over_liboqs"]) if r["pqclean_over_liboqs"] != "" else "-",
            f3(r["openssl_median_us"]) if r.get("openssl_median_us", "") != "" else "-",
            f3(r["hybrid_median_us"]) if r.get("hybrid_median_us", "") != "" else "-"))
    with open(os.path.join(RES, "timing_table.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")

    # --- size table ---
    with open(os.path.join(RES, "size_table.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["algorithm", "implementation", "category", "pk_bytes", "sk_bytes",
                    "sig_bytes", "fips_pk", "fips_sk", "fips_sig", "verdict"])
        for r in size_rows:
            w.writerow([r["algorithm"], r["implementation"], r["category"],
                        r["pk_bytes"], r["sk_bytes"], r["sig_bytes"],
                        r["fips_pk"], r["fips_sk"], r["fips_sig"], r["verdict"]])
    smd = ["# Size table (bytes)",
           "",
           "FIPS 204 Table 2 (ML-DSA-65) and FIPS 205 Table 2 (SLH-DSA), both",
           "published 13 August 2024; SLH-DSA private-key length 4n bytes and",
           "public-key length 2n bytes per FIPS 205 section 3.2. Every measured",
           "size in this pack matches the standard's table for its parameter",
           "set; the verdict column is the check, not a claim.",
           "",
           "| Algorithm | Implementation | Category | pk | sk | sig | FIPS pk | FIPS sk | FIPS sig | Verdict |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for r in size_rows:
        smd.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["algorithm"], r["implementation"], r["category"], r["pk_bytes"],
            r["sk_bytes"], r["sig_bytes"], r["fips_pk"], r["fips_sk"],
            r["fips_sig"], r["verdict"]))
    smd += ["",
            "Classical and hybrid, measured on the same host:",
            "",
            "| Scheme | pk | sk | sig |",
            "|---|---|---|---|",
            "| Ed25519 (OpenSSL 3.0.13) | 32 | 32 | 64 |",
            "| Hybrid Ed25519 + ML-DSA-65 | 32 + 1,952 = 1,984 | 32 + 4,032 = 4,064 | 64 + 3,309 = 3,373 |"]
    with open(os.path.join(RES, "size_table.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(smd) + "\n")

    # --- cost model (derived arithmetic from measured medians) ---
    # Release-signing economics: the signer signs once per release; every
    # operator/verifier verifies. Fleet sizes are assumptions (labelled),
    # the per-operation medians are measured.
    liboqs_128s = by_scheme["SLH-DSA-SHA2-128s"]["liboqs"]
    liboqs_128f = by_scheme["SLH-DSA-SHA2-128f"]["liboqs"]
    pq_128s = by_scheme["SLH-DSA-SHA2-128s"]["pqclean"]
    dsa65 = by_scheme["ML-DSA-65"]["liboqs"]

    def fleet_row(label, sign_us, verify_us, sig_bytes, keygen_us):
        row = {"scenario": label,
               "sign_us_per_release_median": round(sign_us, 3),
               "verify_us_per_verifier_median": round(verify_us, 3),
               "sig_bytes_per_release": sig_bytes,
               "keygen_us_one_time_median": round(keygen_us, 3)}
        for v in (100, 1000, 10000):
            row["verify_cpu_ms_fleet_%d" % v] = round(v * verify_us / 1000.0, 3)
            row["sig_bytes_fleet_%d" % v] = v * sig_bytes
        return row

    rows = [
        fleet_row("Ed25519 alone (OpenSSL, measured)",
                  ed["sign_us"], ed["verify_us"], 64, ed["keygen_us"]),
        fleet_row("Hybrid Ed25519 + ML-DSA-65 (measured)",
                  hyb["sign_us"], hyb["verify_us"], 3373,
                  ed["keygen_us"] + dsa65["keygen_us"]),
        fleet_row("SLH-DSA-SHA2-128s (liboqs, measured)",
                  liboqs_128s["sign_us"], liboqs_128s["verify_us"], 7856,
                  liboqs_128s["keygen_us"]),
        fleet_row("SLH-DSA-SHA2-128s (PQClean clean, measured)",
                  pq_128s["sign_us"], pq_128s["verify_us"], 7856,
                  pq_128s["keygen_us"]),
        fleet_row("SLH-DSA-SHA2-128f (liboqs, measured)",
                  liboqs_128f["sign_us"], liboqs_128f["verify_us"], 17088,
                  liboqs_128f["keygen_us"]),
    ]
    model = {
        "model": "derived arithmetic from measured medians (this pack)",
        "fleet_sizes_assumption": "100 / 1,000 / 10,000 verifiers per release (assumptions, labelled; not measured)",
        "sign_once_verify_many": "the signer signs once per release; every verifier verifies once",
        "per_release_per_verifier": rows,
        "ratios_vs_hybrid": {
            "slh_dsa_sha2_128s_verify_us_over_hybrid_verify_us_liboqs":
                round(liboqs_128s["verify_us"] / hyb["verify_us"], 2),
            "slh_dsa_sha2_128s_sig_bytes_over_hybrid_sig_bytes":
                round(7856 / 3373, 2),
            "slh_dsa_sha2_128f_sig_bytes_over_hybrid_sig_bytes":
                round(17088 / 3373, 2),
            "slh_dsa_sha2_128s_sign_us_over_hybrid_sign_us_liboqs":
                round(liboqs_128s["sign_us"] / hyb["sign_us"], 1),
            "slh_dsa_sha2_128s_keygen_us_over_hybrid_keygen_us_liboqs":
                round(liboqs_128s["keygen_us"] / (ed["keygen_us"] + dsa65["keygen_us"]), 1),
        },
    }
    with open(os.path.join(RES, "cost_model.json"), "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(RES, "cost_model.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "sign_us_per_release_median", "verify_us_per_verifier_median",
                    "sig_bytes_per_release", "keygen_us_one_time_median",
                    "verify_cpu_ms_fleet_100", "verify_cpu_ms_fleet_1000",
                    "verify_cpu_ms_fleet_10000", "sig_bytes_fleet_100",
                    "sig_bytes_fleet_1000", "sig_bytes_fleet_10000"])
        for r in rows:
            w.writerow([r["scenario"], r["sign_us_per_release_median"],
                        r["verify_us_per_verifier_median"], r["sig_bytes_per_release"],
                        r["keygen_us_one_time_median"], r["verify_cpu_ms_fleet_100"],
                        r["verify_cpu_ms_fleet_1000"], r["verify_cpu_ms_fleet_10000"],
                        r["sig_bytes_fleet_100"], r["sig_bytes_fleet_1000"],
                        r["sig_bytes_fleet_10000"]])

    # --- summary.txt ---
    lines = ["Post-quantum release-signing assessment for PFTL",
             "Host: %s, %d cores" % (env["cpu"], env["cores"]),
             "OS: %s" % env["os"],
             "Toolchain: %s, %s, Python %s, %s"
             % (env["gcc"], env["cmake"], env["python"], env["openssl"]),
             "liboqs 0.16.0 (minimal build: ML-DSA-65 + SLH-DSA pure 128s/128f); PQClean commit %s (clean)"
             % env["pqclean_commit"],
             "Correctness: 6/6 liboqs + 5/5 PQClean round-trips PASS; 12/12 negative tests PASS; 5/5 rotation-drill steps PASS",
             "Sizes: all 10 size rows MATCH FIPS 204 Table 2 / FIPS 205 Table 2",
             "",
             "Median microseconds per operation (liboqs | PQClean clean):"]
    for alg in SCHEME_ORDER:
        lq, pq = by_scheme[alg]["liboqs"], by_scheme[alg]["pqclean"]
        lines.append("  %s keygen %.3f | %.3f; sign %.3f | %.3f; verify %.3f | %.3f"
                     % (alg, lq["keygen_us"], pq["keygen_us"],
                        lq["sign_us"], pq["sign_us"],
                        lq["verify_us"], pq["verify_us"]))
    lines.append("  Ed25519 (OpenSSL): keygen %.3f; sign %.3f; verify %.3f"
                 % (ed["keygen_us"], ed["sign_us"], ed["verify_us"]))
    lines.append("  Hybrid Ed25519 + ML-DSA-65: sig 3,373 bytes; sign %.3f us; verify %.3f us"
                 % (hyb["sign_us"], hyb["verify_us"]))
    lines += ["",
              "Headline comparison (liboqs medians, this host):",
              "  Hybrid verify %.3f us vs SLH-DSA-SHA2-128s verify %.3f us (%.2fx);"
              % (hyb["verify_us"], liboqs_128s["verify_us"],
                 liboqs_128s["verify_us"] / hyb["verify_us"]),
              "  Hybrid sign %.3f us vs SLH-DSA-SHA2-128s sign %.3f us (%.1fx);"
              % (hyb["sign_us"], liboqs_128s["sign_us"],
                 liboqs_128s["sign_us"] / hyb["sign_us"]),
              "  Hybrid signature 3,373 bytes vs SLH-DSA-128s 7,856 bytes (%.2fx) and SLH-DSA-128f 17,088 bytes (%.2fx);"
              % (7856 / 3373, 17088 / 3373),
              "  Hybrid keygen %.3f us (Ed25519 + ML-DSA-65) vs SLH-DSA-128s keygen %.3f us (%.1fx)."
              % (ed["keygen_us"] + dsa65["keygen_us"], liboqs_128s["keygen_us"],
                 liboqs_128s["keygen_us"] / (ed["keygen_us"] + dsa65["keygen_us"])),
              "",
              "Recommendation: hybrid Ed25519 + ML-DSA-65 for release signing; SLH-DSA-128s",
              "as the hash-based fallback. See release_signing_assessment.md for the design,",
              "phased costs, rollback protection and key-compromise response.",
              "",
              "Negative tests: 12/12 PASS (tampered manifest, tampered signatures, wrong key,",
              "rollback, revoked key, expired key, for hybrid and SLH-DSA-SHA2-128s).",
              "Rotation drill: 5/5 PASS (new key signs new manifest, old manifest fails under",
              "new key, revocation blocks the old key, new manifest unaffected).",
              "",
              "Reproduction: bash run_all.sh (offline, from the vendored results JSON)."]
    with open(os.path.join(RES, "summary.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # --- docs/index.html ---
    def esc(v):
        return html.escape(str(v))

    def read_optional(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None

    digest_out = read_optional(os.path.join(RES, "digest_check_output.txt"))
    run_log = read_optional(os.path.join(RES, "run_log.txt"))
    run_tail = "\n".join(run_log.splitlines()[-40:]) if run_log else None

    timing_html = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r["algorithm"]), esc(r["operation"]),
            esc(("%.3f" % r["liboqs_median_us"]) if r["liboqs_median_us"] != "" else "-"),
            esc(("%.3f" % r["pqclean_median_us"]) if r["pqclean_median_us"] != "" else "-"),
            esc(("%.2f" % r["pqclean_over_liboqs"]) if r["pqclean_over_liboqs"] != "" else "-"),
            esc(("%.3f" % r["openssl_median_us"]) if r.get("openssl_median_us", "") != "" else "-"),
            esc(("%.3f" % r["hybrid_median_us"]) if r.get("hybrid_median_us", "") != "" else "-"))
        for r in timing_rows)
    size_html = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r["algorithm"]), esc(r["implementation"]), esc(r["category"]),
            esc(r["pk_bytes"]), esc(r["sk_bytes"]), esc(r["sig_bytes"]),
            esc(r["verdict"]))
        for r in size_rows)
    cost_html = "\n".join(
        "<tr><td>%s</td><td>%.3f</td><td>%.3f</td><td>%d</td><td>%.3f</td><td>%.3f</td></tr>" % (
            esc(r["scenario"]), r["sign_us_per_release_median"],
            r["verify_us_per_verifier_median"], r["sig_bytes_per_release"],
            r["verify_cpu_ms_fleet_1000"], r["verify_cpu_ms_fleet_10000"])
        for r in rows)
    neg_html = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(t["id"]), esc(t["description"]), esc(t["expected"]),
            esc(t["got"]), esc(t["result"]))
        for t in liboqs["negative_tests"])
    rot_html = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(t["id"]), esc(t["description"]), esc(t["expected"]),
            esc(t["got"]), esc(t["result"]))
        for t in liboqs["rotation_drill"])
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Post-Quantum Release-Signing Assessment for PFTL</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  max-width:960px;margin:2em auto;padding:0 1em;color:#111;line-height:1.5}
h1{font-size:1.6em}h2{font-size:1.25em;margin-top:1.5em}
table{border-collapse:collapse;width:100%%;margin:1em 0}
th,td{border:1px solid #ccc;padding:.35em .6em;text-align:left;
  font-size:.92em}th{background:#f0f0f0}
code{background:#f4f4f4;padding:0 .2em}
.callout{background:#f7f3e8;border-left:4px solid #b58900;padding:.7em 1em}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85em;
  white-space:pre-wrap;word-break:break-word;background:#f8f8f8;
  border:1px solid #ddd;padding:1em;overflow-x:auto}
</style>
</head>
<body>
<h1>Post-Quantum Release-Signing Assessment for PFTL</h1>
<p>Measured signing costs for a hybrid Ed25519 + ML-DSA-65 release
scheme against SLH-DSA, with negative tests, a key-rotation drill,
and a mapping to the release and signing code in postfiatd (pinned
commit <code>0085a1ff885d6a446369cf73a4430f75af22be55</code>).</p>

<div class="callout"><strong>Headline finding.</strong> The hybrid
scheme wins on every measured axis on this host. Hybrid verification
costs <strong>%.3f &micro;s (median)</strong> against
<strong>%.3f &micro;s</strong> for SLH-DSA-SHA2-128s (liboqs) —
about %.2f&times; faster — and a hybrid signature is
<strong>3,373 bytes</strong> against 7,856 bytes for SLH-DSA-128s
and 17,088 bytes for SLH-DSA-128f. Signing is the starkest gap:
hybrid signing costs %.3f &micro;s while SLH-DSA-128s signing costs
%.3f &micro;s (liboqs), about %.1f&times; more, because the
small-signature SLH-DSA parameter sets trade signing time for size.
Recommendation: sign releases with hybrid Ed25519 + ML-DSA-65 now,
keep SLH-DSA-128s as the hash-based fallback in case lattice schemes
fail.</div>

<h2>Host and toolchain</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>CPU</td><td>%s (%d cores)</td></tr>
<tr><td>OS</td><td>%s</td></tr>
<tr><td>Compiler</td><td>%s</td></tr>
<tr><td>liboqs</td><td>0.16.0 — minimal build (ML-DSA-65 + SLH-DSA pure 128s/128f, SHA2 and SHAKE)</td></tr>
<tr><td>PQClean</td><td>commit %s — portable-C <code>clean</code> reference implementations</td></tr>
<tr><td>OpenSSL (Ed25519 baseline)</td><td>%s</td></tr>
<tr><td>OpenSSL 3.5 (third implementation)</td><td>NOT MEASURED — see claim index</td></tr>
</table>

<h2>Timing table (median &micro;s per operation)</h2>
<p>Each operation is the median of 11 single-shot measurements
(<code>clock_gettime(CLOCK_MONOTONIC)</code>). liboqs runs its
optimized x86_64 path; PQClean <code>clean</code> is portable C — the
ratio column compares an optimized implementation against a
reference, not two equals. The manifest signed is a canonical
<code>PFTL-RELEASE-MANIFEST-v1</code> document (artifact name,
version, artifact SHA-256, key id, not-after); the artifact hashed
is a deterministic 1 MiB payload (SHA-256 %.3f &micro;s). Full
statistics and unedited raw logs are in <code>results/</code>.</p>
<table>
<tr><th>Algorithm</th><th>Operation</th><th>liboqs median (&micro;s)</th>
<th>PQClean median (&micro;s)</th><th>PQClean / liboqs</th><th>OpenSSL median (&micro;s)</th><th>Hybrid median (&micro;s)</th></tr>
%s
</table>

<h2>Size table (bytes)</h2>
<p>FIPS 204 Table 2 (ML-DSA-65) and FIPS 205 Table 2 (SLH-DSA), both
published 13 August 2024; SLH-DSA private-key length 4n bytes and
public-key length 2n bytes per FIPS 205 section 3.2. Every measured
size matches the standard. The hybrid row is the sum of its two
components (Ed25519 32/32/64 + ML-DSA-65 1,952/4,032/3,309).</p>
<table>
<tr><th>Algorithm</th><th>Implementation</th><th>Category</th>
<th>pk</th><th>sk</th><th>sig</th><th>Verdict</th></tr>
%s
</table>

<h2>Release cost model (derived)</h2>
<p>Per release, per verifier, from the measured medians. The signer
signs once per release; every verifier verifies once. Fleet sizes
(100 / 1,000 / 10,000 verifiers) are assumptions, labelled as such.
See <code>results/cost_model.json</code> for the machine-readable
form and <code>release_signing_assessment.md</code> for the design.</p>
<table>
<tr><th>Scenario</th><th>Sign (&micro;s/release)</th><th>Verify (&micro;s/verifier)</th>
<th>Signature bytes / release</th><th>Verify CPU, 1,000 verifiers (ms)</th><th>Verify CPU, 10,000 verifiers (ms)</th></tr>
%s
</table>

<h2>Negative tests (12/12 PASS)</h2>
<p>Each test asserts the verifier rejects the manifest with the
expected reason. Run by <code>harness/sign_release.c</code>; raw log
<code>results/raw_sign_liboqs.log</code>.</p>
<table>
<tr><th>ID</th><th>Test</th><th>Expected</th><th>Got</th><th>Result</th></tr>
%s
</table>

<h2>Key-rotation drill (5/5 PASS)</h2>
<p>Key v1 signs manifest v3 (installed v2); a new key v2 signs
manifest v4 (installed v3); the old manifest fails under the new
key; revoking v1 blocks the old manifest; the new manifest is
unaffected by the v1 revocation.</p>
<table>
<tr><th>ID</th><th>Step</th><th>Expected</th><th>Got</th><th>Result</th></tr>
%s
</table>

<h2>Call-site mapping</h2>
<p>postfiatd has no release-artifact signing: <code>docs/RELEASE.md</code>
describes a version-string + Docker-tag + GitHub Release process with
no artifact signatures or checksums. The closest real code is the
validator manifest system — <code>src/xrpld/app/misc/Manifest.h:66-77</code>
(ephemeral-key compromise response and revocation) and
<code>src/xrpld/app/misc/detail/Manifest.cpp:196</code>
(<code>Manifest::verify</code>) — and transaction/validation signing
in <code>src/libxrpl/protocol/SecretKey.cpp:230-276</code>
(<code>signDigest</code> secp256k1, <code>sign</code> Ed25519) and
<code>src/libxrpl/protocol/STValidation.cpp:131-141</code>
(validation <code>verifyDigest</code>). Full mapping in
<code>call_sites.md</code>.</p>

<h2>Digest-check output</h2>
<p>Raw output of <code>bash verify_digests.sh --check</code> (SHA-256
manifest over every pack file except the manifest itself):</p>
<pre class="mono">%s</pre>

<h2>Run-log tail</h2>
<p>Tail of <code>results/run_log.txt</code> — the raw console log of
the fresh-copy reproduction run (<code>bash run_all.sh</code>, exit 0):</p>
<pre class="mono">%s</pre>

<h2>Reproduction</h2>
<p class="mono">bash run_all.sh</p>
<p>Regenerates every derived output offline from the vendored results
JSON (<code>results/signing_*.json</code>), rebuilds this page, and
verifies digests. Expected: exit 0, byte-identical outputs. See
<code>REPRODUCTION.md</code> for the exact command and recorded
result. To re-run the signing measurements themselves (not part of
the offline reproduction — timings vary run to run), see
<code>harness/build_signing.sh</code> and
<code>harness/run_signing.sh</code>.</p>

<h2>Files</h2>
<ul>
<li><code>results/signing_liboqs.json</code>,
<code>results/signing_pqclean_*.json</code> — vendored raw signing
results (JSON)</li>
<li><code>results/raw_sign_liboqs.log</code>,
<code>results/raw_sign_pqclean_*.log</code> — unedited raw console logs</li>
<li><code>results/timing_table.csv</code> /
<code>timing_table.md</code>, <code>results/size_table.csv</code> /
<code>size_table.md</code> — derived tables</li>
<li><code>results/cost_model.json</code> / <code>cost_model.csv</code> —
derived release cost model</li>
<li><code>results/summary.txt</code> — headline numbers in plain text</li>
<li><code>results/environment.json</code> — host, toolchain, versions</li>
<li><code>results/digest_check_output.txt</code>,
<code>results/run_log.txt</code> — digest-check output, reproduction log</li>
<li><code>harness/sign_release.c</code>,
<code>harness/sign_pqclean.c</code> — signing drivers</li>
<li><code>harness/build_signing.sh</code>,
<code>harness/run_signing.sh</code> — build / run scripts</li>
<li><code>call_sites.md</code> — measurement-to-call-site mapping</li>
<li><code>release_signing_assessment.md</code> — hybrid design,
rotation/revocation, phased costs, forward-only activation, rollback,
exposure-ranked priorities</li>
<li><code>claim_evidence_index.md</code> — measured vs source-derived
claims, separated, with file:line and output-file references</li>
<li><code>sources.md</code> — primary sources and version pins</li>
<li><code>sources/NIST.FIPS.204.pdf</code>,
<code>sources/NIST.FIPS.205.pdf</code> — vendored standards</li>
</ul>

<h2>Limitations</h2>
<ul>
<li>Timings are for this host and toolchain only (shared virtual CPU,
gcc 13.3.0, -O2). They do not transfer to release or validator
hardware; the ratios between schemes on one host are the portable
part. SLH-DSA-128s signing is slow in both reference implementations
here (hundreds of milliseconds to over a second); optimized
implementations would be faster, but the ordering (128f much faster
to sign than 128s, hybrid fastest) is structural.</li>
<li>liboqs uses its optimized x86_64 path; PQClean <code>clean</code> is
portable C. A production deployment would use optimized code for both
schemes; the PQClean numbers are a conservative upper bound.</li>
<li>OpenSSL 3.5 was not measured (see the claim index): the system
OpenSSL is 3.0.13, which has no native ML-DSA or SLH-DSA.</li>
<li>The test keys are ephemeral, generated fresh on every run, and
never written to disk. The manifest format is a proposal for the
assessment, not a deployed format.</li>
<li>No release was signed or published for postfiatd; no ledger was
compiled or run locally.</li>
</ul>
</body>
</html>
""" % (
        hyb["verify_us"], liboqs_128s["verify_us"],
        liboqs_128s["verify_us"] / hyb["verify_us"],
        hyb["sign_us"], liboqs_128s["sign_us"],
        liboqs_128s["sign_us"] / hyb["sign_us"],
        esc(env["cpu"]), env["cores"], esc(env["os"]),
        esc(env["gcc"]), esc(env["pqclean_commit"]),
        esc(env["openssl"]),
        liboqs["artifact"]["hash_us"],
        timing_html,
        size_html,
        cost_html,
        neg_html,
        rot_html,
        esc(digest_out) if digest_out else "NOT YET RECORDED — run `bash verify_digests.sh --check > results/digest_check_output.txt` and rebuild.",
        esc(run_tail) if run_tail else "NOT YET RECORDED — run `bash run_all.sh` in a fresh copy and capture its console log to results/run_log.txt, then rebuild.",
    )
    with open(os.path.join(PACK, "docs", "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)
    print("build_derived.py: OK (timing/size/cost tables, summary, docs/index.html)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
