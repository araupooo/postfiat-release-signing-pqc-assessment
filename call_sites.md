# Call-site mapping (postfiatd, pinned commit 0085a1ff)

Every measurement in this pack is mapped to the code it would touch
in postfiatd. The pinned tree is
`/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`, HEAD
`0085a1ff885d6a446369cf73a4430f75af22be55`.

## The gap (finding)

postfiatd has **no release-artifact signing**. The release process
(`docs/RELEASE.md:5-28`) is: bump the version string in
`src/libxrpl/protocol/BuildInfo.cpp:39` (`versionString = "1.0.9"`),
commit, merge to a network branch, and let the CI/CD pipeline build
Docker images and publish a GitHub Release `v{version}`. The release
notes are generated from merged PRs, and the release is the public
announcement feed (operators poll
`https://github.com/postfiatorg/postfiatd/releases.atom`). There is no
step that signs an artifact, publishes a checksum, or verifies one on
download. Image tags are overwrite-protected by a Docker Hub tag check
(`docs/RELEASE.md:31-50`), which is a uniqueness guard, not an
authenticity check. **Any operator downloading a release today trusts
the GitHub/Docker transport, not a signature.** The hybrid scheme
measured in this pack is the proposed fix for exactly that gap.

## Measured scheme → in-tree code it would touch

| Measurement (this pack) | postfiatd call site (pinned tree) | What changes |
|---|---|---|
| Hybrid Ed25519 + ML-DSA-65 signing of a release manifest (sign 139.669 us, verify 190.366 us, sig 3,373 B) | NEW code. No existing release signer. The closest pattern is `scripts/sign_exclusion_list.py:1-14`, which signs an exclusion-list JSON with NaCl Ed25519 for `RemoteExclusionListFetcher` verification — a signed-JSON-list precedent in-tree | A release signer would produce a signed manifest (artifact name, version, artifact SHA-256, key id, not-after) exactly like the one measured here, and a verifier would check it before installing |
| Ed25519 signing/verification (sign 52.839 us, verify 140.972 us) | `src/libxrpl/protocol/SecretKey.cpp:260-276` (`sign`: Ed25519 branch `:263-265`, `ed25519_sign`, 64-byte signatures); verification via `verifyDigest` in `src/libxrpl/protocol/PublicKey.cpp:239` | Ed25519 is already a first-class signing primitive in postfiatd; the hybrid scheme reuses it unchanged |
| ML-DSA-65 signing/verification (sign 136.475 us, verify 47.260 us) | NO in-tree code. postfiatd pins OpenSSL 1.1.1w (`conanfile.py:30`), which has no ML-DSA. ML-DSA would arrive via liboqs (as used for these measurements) or OpenSSL 3.5+ | New dependency (liboqs) or OpenSSL upgrade; the measured ML-DSA-65 verify (47.260 us) is faster than the Ed25519 verify it would sit beside |
| SLH-DSA-128s/128f signing/verification | NO in-tree code. Same dependency story as ML-DSA-65 | Fallback only (see assessment): SLH-DSA-128s signing costs 692,670.570 us (liboqs) per manifest — acceptable once per release, but the keygen cost (91,472.097 us) and 7,856-byte signatures make it a poor primary |
| Rollback protection (N5: manifest v2 vs installed v3 rejected) | `docs/RELEASE.md:31-50` — Docker tag overwrite protection ("fails if the version already exists") is the only version guard today, and it lives in CI, not in the artifact | The manifest's `version` field plus an installed-version check (as measured) moves the guard into the artifact itself |
| Key revocation (N6, R4: revoked key_id rejected) | `src/xrpld/app/misc/detail/Manifest.cpp:120-156` (revocation manifests), `:196-230` (`Manifest::verify`), `:43` (`revoked()`); design in `src/xrpld/app/misc/Manifest.h:66-77` | The validator-manifest revocation pattern (sequence number 0xFFFFFFFF supersedes; no further manifests accepted) is directly reusable for release keys — see the assessment |
| Key rotation drill (R1–R5) | `src/xrpld/app/misc/Manifest.h:66-77` — "When an ephemeral key is compromised, a new signing key pair is created, along with a new manifest vouching for it (with a higher sequence number), signed by the master key" | The drill measured here (new key, re-sign, old manifest fails under new key, revocation blocks old key) mirrors this exact flow with release keys instead of validator ephemeral keys |
| Validation signing (context: what PQC must NOT break) | `src/libxrpl/protocol/STValidation.cpp:125-141` (`verifyDigest` gate, secp256k1-only: `publicKeyType(getSignerPublic()) == KeyType::secp256k1`); `src/libxrpl/protocol/SecretKey.cpp:230-250` (`signDigest`, secp256k1 ECDSA DER) | Validation signing is out of scope for release signing, but any future migration of it must respect the secp256k1-only gate at STValidation.cpp:131-139 — the lattice pack measured ML-DSA-65 verify at 47.260 us against secp256k1 verify at 558.113 us on the same host family, so the CPU case is already made there |
| Transaction signing (context) | `src/libxrpl/protocol/Sign.cpp:34` (`sign`), `:48` (`verify`), `:96` (`buildMultiSigningData`) | Same primitives as release signing; the hybrid design reuses the Ed25519 path and adds ML-DSA-65 beside it |

## What was NOT found (checked, absent)

- No `*.sig`, `*.asc`, `SHA256SUMS`, or checksum file is produced or
  verified anywhere in the release workflow (`docs/RELEASE.md`,
  `.github/`, `scripts/` — searched for `checksum`, `sha256sum`,
  `gpg`, `cosign`, `sign_exclusion`; the only match is
  `scripts/sign_exclusion_list.py`, which signs exclusion lists, not
  releases).
- No `release` signing key, key id, or not-after/expiry concept in
  the release process.
- No SLH-DSA, ML-DSA, or liboqs reference anywhere in the tree.
