# PFTL Post-Quantum Release-Signing Assessment

## Summary

**Recommendation: sign every PFTL release with hybrid Ed25519 +
ML-DSA-65, and keep SLH-DSA-SHA2-128s as a hash-based fallback.**

The hybrid scheme wins on every measured axis on this host. Hybrid
verification costs 190.366 us (median) against 710.776 us for
SLH-DSA-SHA2-128s — 3.73x faster — and a hybrid signature is 3,373
bytes against 7,856 bytes for SLH-DSA-128s and 17,088 bytes for
SLH-DSA-128f. The signing gap is the starkest: hybrid signing costs
139.669 us while SLH-DSA-128s signing costs 692,670.570 us, about
4,959.4x more, because the small-signature SLH-DSA parameter sets
trade signing time for size (128s uses a 9-level hypertree with
63 total height; 128f uses 22 levels of height 3 and signs 20.6x
faster but with 2.18x larger signatures). The cost is one extra
signature scheme to verify — and ML-DSA-65 verification alone is
47.260 us, faster than the Ed25519 verification (140.972 us) it sits
beside.

Why hybrid rather than ML-DSA-65 alone: if a cryptanalytic break in
ML-DSA-65 is published, the Ed25519 signature still binds the
release to the release key; if a quantum computer breaks Ed25519,
the ML-DSA-65 signature still binds it. Both signatures must verify
for the release to install, so a single-scheme break does not forge a
release. That is the whole point of hybrid signing for a release
artifact that must survive the decade it takes to migrate a network.

Why not SLH-DSA as the primary: its verify cost (710.776 us for
128s, 2,005.969 us for 128f) is tolerable for a one-time install, but
its signing cost (692,670.570 us for 128s) and keygen cost
(91,472.097 us) make emergency re-signing slow, and its 7,856–17,088
byte signatures bloat every manifest. Its value is diversity: it is
hash-based, so a break in lattice cryptography does not touch it. It
belongs in the manifest as a third, optional signature — not as the
primary.

## Finding: postfiatd has no release-artifact signing today

The release process (`docs/RELEASE.md:5-28`, pinned commit
`0085a1ff`) is: bump the version string in
`src/libxrpl/protocol/BuildInfo.cpp:39` (`versionString = "1.0.9"`),
commit, merge, and let CI/CD build Docker images and publish a GitHub
Release `v{version}`. The release notes are generated from merged PRs
and the release is the public announcement feed. There is no step
that signs an artifact, publishes a checksum, or verifies one on
download, and no release signing key, key id, or expiry concept
anywhere in the process. Docker tag overwrite protection
(`docs/RELEASE.md:31-50`) is a uniqueness guard in CI, not an
authenticity check. **An operator downloading a release today trusts
the GitHub/Docker transport, not a signature.** That is the exposure
this assessment addresses.

The closest in-tree precedent is `scripts/sign_exclusion_list.py`,
which signs an exclusion-list JSON with NaCl Ed25519 for
`RemoteExclusionListFetcher` verification — a signed-JSON-list
pattern the release manifest can copy directly. The validator
manifest system (`src/xrpld/app/misc/Manifest.h:66-77`,
`src/xrpld/app/misc/detail/Manifest.cpp:196-230`) already implements
the rotation and revocation semantics a release-key system needs:
higher sequence number supersedes, master key revokes with sequence
0xFFFFFFFF, no further manifests accepted after revocation.

## Measured results

Host: AMD EPYC 9D25, 4 cores, Ubuntu 24.04.5 LTS, gcc 13.3.0,
liboqs 0.16.0 (minimal build: ML-DSA-65 + SLH-DSA pure 128s/128f),
PQClean commit 0586a824 (clean), OpenSSL 3.0.13. Medians of 11
single-shot measurements; full tables in `results/timing_table.md`
and `results/size_table.md`.

### Sizes (all MATCH FIPS 204 Table 2 / FIPS 205 Table 2)

| Scheme | pk (B) | sk (B) | sig (B) |
|--------|--------|--------|---------|
| Ed25519 | 32 | 32 | 64 |
| ML-DSA-65 | 1,952 | 4,032 | 3,309 |
| Hybrid Ed25519 + ML-DSA-65 | 1,984 | 4,064 | **3,373** |
| SLH-DSA-128s (SHA2 / SHAKE) | 32 | 64 | 7,856 |
| SLH-DSA-128f (SHA2 / SHAKE) | 32 | 64 | 17,088 |

### Timings, median us per operation (liboqs | PQClean clean)

| Scheme | keygen | sign | verify |
|--------|--------|------|--------|
| Ed25519 (OpenSSL) | 54.552 | 52.839 | 140.972 |
| ML-DSA-65 | 47.642 \| 269.624 | 136.475 \| 917.155 | 47.260 \| 241.773 |
| Hybrid Ed25519 + ML-DSA-65 | 102.194 | 139.669 | **190.366** |
| SLH-DSA-SHA2-128s | 91,472.097 \| 108,510.735 | 692,670.570 \| 847,707.555 | 710.776 \| 805.448 |
| SLH-DSA-SHAKE-128s | 166,742.031 \| 243,960.129 | 1,282,924.657 \| 1,872,710.000 | 1,177.146 \| 1,691.808 |
| SLH-DSA-SHA2-128f | 1,415.873 \| 2,579.089 | 33,670.295 \| 56,852.949 | 2,005.969 \| 3,327.451 |
| SLH-DSA-SHAKE-128f | 2,653.170 \| 3,727.792 | 62,060.040 \| 89,146.539 | 3,707.982 \| 5,410.406 |

Test artifact: deterministic 1 MiB payload, SHA-256
`fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`,
hash time 2,711.077 us. Correctness: 6/6 liboqs + 5/5 PQClean
round-trips PASS.

Method note: all timings are medians of 11 single-shot measurements.
ML-DSA signing uses rejection sampling, so per-run medians vary; the
hybrid medians and the standalone scheme medians come from separate
runs of the same harness, so a hybrid median need not equal the sum of
the standalone medians. Every median is quoted exactly as the raw logs
print it.

Two things the numbers say that are easy to miss:

1. **SLH-DSA-128s signing is genuinely slow, not a measurement
   bug.** Both independent implementations agree (692,670.570 us
   liboqs, 847,707.555 us PQClean clean) and the keygen cost scales
   with the hypertree structure (128s: h'=9, keygen 91,472.097 us;
   128f: h'=3, keygen 1,415.873 us). The 128s parameter set buys its
   small signature with signing work.
2. **PQClean clean is 1.1x–6.7x slower than liboqs on the same
   scheme** (ML-DSA-65 sign 917.155 vs 136.475 us, 6.72x; SLH-DSA
   verify 1.13x–1.82x). Sizes are identical in both implementations,
   which is the cross-check that matters: the numbers are
   implementation-independent, the timings are not.

## The proposed manifest

Measured in `harness/sign_release.c` as
`PFTL-RELEASE-MANIFEST-v1`:

```
PFTL-RELEASE-MANIFEST-v1
artifact: postfiatd-1.0.9-linux-x86_64.tar.gz
version: 3
sha256: <64 hex chars of the artifact>
key_id: release-key-v1
not_after: 2030-01-01T00:00:00Z
```

Two signatures are computed over the manifest bytes (Ed25519 +
ML-DSA-65, 3,373 bytes total) and, for the fallback, a third
SLH-DSA-SHA2-128s signature (7,856 bytes). The verifier:

1. rejects a manifest whose `key_id` is revoked or whose
   `not_after` has passed;
2. rejects a manifest whose `version` is lower than the installed
   version (rollback protection);
3. verifies the artifact SHA-256 against the manifest;
4. verifies both hybrid signatures over the manifest bytes;
5. installs only if every check passes.

Negative tests, all measured in this pack (12/12 PASS):

- N1 tampered manifest body → ML-DSA-65 verification fails;
- N2 tampered ML-DSA-65 signature → fails;
- N3 tampered Ed25519 signature → fails;
- N4 wrong public key → fails;
- N5 rollback (manifest version 2, installed version 3) → rejected;
- N6 revoked key_id → rejected;
- N7 expired not_after → rejected;
- N8 clean-manifest control → verifies;
- N9 SLH-DSA-SHA2-128s control → verifies;
- N10 tampered manifest under SLH-DSA → fails;
- N11 tampered SLH-DSA signature → fails;
- N12 wrong SLH-DSA public key → fails.

## Key rotation and key compromise

Measured rotation drill (5/5 PASS):

- R1 release key v1 signs manifest v3;
- R2 release key v2 signs manifest v4;
- R3 the v3 manifest fails under v2 keys (keys are not interchangeable);
- R4 revoking key v1 blocks the old manifest;
- R5 the new manifest is unaffected by the revocation.

Compromise response, following the validator-manifest pattern
(`Manifest.h:66-77`):

1. **Release key compromised:** publish a revocation entry for the
   key id (as the manifest system does with sequence 0xFFFFFFFF),
   generate a new release key, re-sign the current release with the
   new key at a higher manifest version, and publish. Verifiers that
   have the revocation list reject the old signatures (measured: N6,
   R4). The re-sign cost is one hybrid sign: 139.669 us.
2. **Release key lost:** same flow — the old key is revoked by key
   id, not by possession of the key.
3. **Master/authority key compromised:** rotate the authority key,
   re-issue the release-key endorsements, and re-sign all supported
   releases. This is the slow path and the reason the release key
   should be distinct from the authority key: a release-key
   compromise must never require re-issuing the authority.
4. **ML-DSA-65 broken (cryptanalysis or quantum):** the Ed25519
   signature still binds the release; ship a manifest with the
   SLH-DSA-128s signature as the second factor and retire ML-DSA-65
   in the next release. Signing a SLH-DSA-128s fallback signature
   costs 692,670.570 us once per release — acceptable for an
   emergency re-sign, unacceptable as the routine path.
5. **Ed25519 broken (quantum):** the ML-DSA-65 signature still
   binds the release; same retirement flow in reverse.

## Phased costs

Sign-once / verify-many. The signer signs once per release; every
verifier verifies once. Fleet sizes (100 / 1,000 / 10,000 verifiers)
are assumptions, labelled as such; the per-verifier numbers are
measured. Full model in `results/cost_model.json`.

| Scenario | sign / release | verify / verifier | sig bytes / release | verify CPU, 1,000 verifiers | sig bytes, 1,000 verifiers |
|----------|---------------:|------------------:|--------------------:|----------------------------:|---------------------------:|
| Ed25519 alone | 52.839 us | 140.972 us | 64 | 140.972 ms | 64,000 |
| **Hybrid Ed25519 + ML-DSA-65** | **139.669 us** | **190.366 us** | **3,373** | **190.366 ms** | **3,373,000** |
| SLH-DSA-SHA2-128s (liboqs) | 692,670.570 us | 710.776 us | 7,856 | 710.776 ms | 7,856,000 |
| SLH-DSA-SHA2-128f (liboqs) | 33,670.295 us | 2,005.969 us | 17,088 | 2,005.969 ms | 17,088,000 |

At 10,000 verifiers the hybrid fleet verify cost is 1,903.66 ms of
CPU in total and 33.73 MB of signatures downloaded — against
7,107.76 ms / 78.56 MB for SLH-DSA-128s and 20,059.69 ms / 170.88 MB
for SLH-DSA-128f. The signing cost is paid once per release and is
negligible for the hybrid (139.669 us) and the 128f (33.670 ms), but
is 0.69 s for SLH-DSA-128s — fine for a scheduled release, a
liability for an emergency re-sign under time pressure.

Phasing:

- **Phase 0 — manifest + verifier (no signing yet).** Publish the
  manifest format with artifact SHA-256 and version, and ship a
  verifier that checks hash + version. Cost: one hash per artifact
  (2,711.077 us for 1 MiB). Closes the "no integrity check at all"
  gap before any cryptography lands.
- **Phase 1 — hybrid signing.** Generate the release key, sign
  manifests with Ed25519 + ML-DSA-65, publish the public keys
  out-of-band (pinned in the repo and in the release notes). Cost
  per release: 139.669 us sign, 3,373 bytes. Verifiers enforce both
  signatures.
- **Phase 2 — revocation + rotation.** Publish the revocation list
  format and the rotation drill (measured here as R1–R5). Cost: one
  re-sign per rotation (139.669 us). This is the phase that turns
  signing from a feature into an incident-response capability.
- **Phase 3 — SLH-DSA fallback.** Add the optional third signature
  (SLH-DSA-SHA2-128s, 7,856 bytes, 692,670.570 us to sign once per
  release) and a policy flag to require it when the lattice scheme
  is distrusted. Cost: paid only when the fallback is enabled.

## Exposure-ranked priorities

1. **Publish artifact hashes (Phase 0).** Today an operator has no
   way to detect a tampered download at all. A hash in the manifest
   is the cheapest possible fix and needs no key management.
2. **Sign with the hybrid scheme (Phase 1).** The measured cost is
   139.669 us to sign and 190.366 us to verify per release — the
   cheapest meaningful authenticity guarantee available, and the
   only one that survives a single-scheme break.
3. **Ship the revocation list (Phase 2).** A signature without a
   revocation path is a liability the day a key is compromised; the
   validator manifest system already shows how to do it.
4. **Add the SLH-DSA fallback (Phase 3).** Only after the hybrid is
   deployed. Its signing cost makes it an emergency tool, not a
   routine one.

## Limitations

- All timings are from one shared virtual host; ratios (hybrid
  verify 3.73x faster than SLH-DSA-128s verify, 4,959.4x faster to
  sign) are the portable part, absolute microseconds are not.
- Only reference-C (PQClean clean) and liboqs x86_64 builds were
  measured; optimized (AVX2) SLH-DSA implementations would be
  faster. OpenSSL 3.5 native ML-DSA/SLH-DSA was not measured
  (system OpenSSL is 3.0.13).
- Only ML-DSA-65 and the SLH-DSA 128s/128f parameter sets were
  measured; ML-DSA-44/87 and SLH-DSA-192s/256s were not.
- The manifest format and the phased design are a proposal. No
  release signing exists in the pinned postfiatd tree, so nothing
  here has been tested against a deployed verifier.
- Fleet sizes in the cost model are assumptions, not measurements.
