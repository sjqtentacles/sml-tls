# `cakeml/` — CakeML crypto-tower port (Track B2)

This directory holds the **CakeML subset/basis port** of the sjqtentacles
crypto tower (Track B2, Phase 6). It starts at Phase 0 and runs in
parallel with all functional work, because the crypto libraries are
already stable — only the TLS-specific code waits for J2 (then it ports
at J3).

## What goes here

One `<lib>.sml` port per library, fanned out by the dependency DAG:

- **L0 (no deps, 5 parallel workers):** `sml-codec` (SHA-256),
  `sml-bigint`, `sml-aes`, `sml-chacha20`, `sml-x25519`.
- **L1 (after L0):** `sml-pem`, `sml-crypto` (HMAC), `sml-asn1`, `sml-aead`.
- **L2 (after L1):** `sml-kdf`, `sml-rsa`.
- **L3:** `sml-x509`.
- **L4 (J3, after J2 stabilises the functional code):** the `sml-tls`
  sources themselves.

Each port is a *separate file* from the original SML — never edit the
originals. The MLton/Poly build stays green in parallel as the porting
oracle.

## Spike first

The **SHA-256 spike** (L0) is the go/no-go gate for the CakeML dialect
before fanning out the rest of the tower: port it, build it under
CakeML, and diff its output against the MLton `sml-codec` vectors.

## Toolchain to pin

- **CakeML:** pin a tagged release (record the exact commit in
  `cakeml/CAKEML_VERSION` once the spike lands).
- **HOL4:** the CakeML translator (`ml_translatorLib` / `cv` tooling)
  requires a matching HOL4 build (record in `cakeml/HOL4_VERSION`).

These are added by the B2 sub-agent; this README is the Phase 0
placeholder.
