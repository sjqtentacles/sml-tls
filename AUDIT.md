# External security audit — scope and readiness package

This document is the audit-readiness package for `sml-tls`. It is the
concrete deliverable for the "commission an external security audit" gate:
it gives an external auditor everything needed to scope, price, and execute
a review. **Commissioning the audit itself (selecting and engaging a firm)
is a business action the maintainer must take; this document prepares for
it.**

Track 1 (practical security: constant-time crypto via FFI, memory zeroing,
PSK resumption) is complete, which is the prerequisite for a meaningful
audit. See [`SECURITY.md`](SECURITY.md) for the current security/correctness
boundary and [`proof/PROOF_STATUS.md`](proof/PROOF_STATUS.md) /
[`proof/PROOF_CHAIN.md`](proof/PROOF_CHAIN.md) for the formal-verification
status.

---

## 1. What to audit (scope)

`sml-tls` is a pure-Standard-ML TLS 1.3 (RFC 8446) client and server, with an
optional `sml-crypto-ffi` shim that routes X25519 and ChaCha20-Poly1305 to
libsodium for constant-time execution. The audit should cover:

1. **Protocol state machine** (`lib/github.com/sjqtentacles/sml-tls/tlsstate.sml`,
   `tls.sml`): handshake sequencing, transcript-hash handling, alert
   generation, KeyUpdate, NewSessionTicket, HelloRetryRequest, and the new
   **PSK resumption accept path** (ticket store, binder verification,
   `selected_identity` handling).
2. **Wire codecs** (`tls.sml`, `extensions.sml`, `recordprotect.sml`,
   `certverify.sml`): parsing robustness against malformed/adversarial input,
   length-field handling, integer-overflow / truncation behavior.
3. **Certificate validation** (`certverify.sml`, vendored `sml-x509`):
   chain construction, signature verification, basic-constraints / path-length,
   hostname matching, validity windows.
4. **Crypto integration boundary** (`sml-crypto-ffi/`): the FFI marshalling to
   libsodium (length handling, error propagation, tag verification), and the
   residual pure-SML primitives (AES-GCM, RSA-PSS) that are **not** constant-time.
5. **Key lifecycle** (`SecureZero`, `zeroize` / `zeroizeConfig`): whether key
   material is erased on teardown and the documented best-effort limits.

### Explicitly out of scope (already documented as trusted/assumed)
- The cryptographic *strength* of SHA-256/HMAC/AEAD/X25519/RSA primitives
  (assumed, not derived — standard for an implementation audit).
- The libsodium internals (separately audited upstream).
- The CakeML compiler correctness proof (upstream formal result).

---

## 2. Threat model

- **In scope:** a network adversary (active MITM) sending arbitrary bytes;
  malformed handshake/record inputs; malicious certificate chains; replay /
  resumption-ticket abuse; downgrade attempts.
- **Timing side channels:** in scope **for the FFI-backed primitives**
  (X25519, ChaCha20-Poly1305 via libsodium — expected constant-time) and as a
  **known residual risk** for the pure-SML AES-GCM and RSA-PSS paths, which are
  variable-time and documented as such. The auditor should confirm the residual
  variable-time surface and advise on FFI-izing AES-GCM/RSA if required for the
  deployment.
- **Out of scope:** physical attacks, compromised host OS, supply-chain of the
  SML compilers (MLton/Poly/ML) and libsodium.

---

## 3. Audit deliverables already prepared

### 3.1 Conformance & differential harnesses (`sml-tls-tool`)
- **OpenSSL differential** — `sml-tls-tool/scripts/run_openssl_diff.sh`:
  drives a full TLS 1.3 handshake against `openssl s_server` via a socket shim.
- **BoGo subset** — `sml-tls-tool/scripts/run_bogo.sh`,
  `cli/bogo_main.sml`: BoringSSL's protocol test runner against the SML stack.
- **tlsfuzzer** — `sml-tls-tool/scripts/run_tlsfuzzer.sh`.
- **AFL fuzz harnesses** — `sml-tls-tool/fuzz/`: per-codec entry points
  (`afl_clienthello`, `afl_serverhello`, `afl_certificate`, `afl_ciphertext`,
  `afl_record`, `afl_recordprotect`, `afl_extensions`) plus `run_afl.sh`.
  Prior run: 33 000+ inputs crash-free on the parser entry points.

### 3.2 Test suite
- 306 passing tests on **both** MLton and Poly/ML (`make test && make test-poly`),
  including RFC 8448 vectors, round-trip and tamper/negative tests, the PSK
  resumption accept + negative-binder tests, the FFI cross-implementation
  byte-equality tests, and the zeroize tests.

### 3.3 Formal-verification artifacts
- `proof/` — 5 HOL4 theories, `Holmake cleanAll && Holmake` clean,
  **0 axioms, 0 cheats, 0 custom oracles**. Wire round-trips (incl. all four
  hello/cert/ticket codecs), RFC 8448 key-schedule vectors against a concrete
  SHA-256, handshake safety invariants, and CakeML↔spec codec refinement.
- `proof/PROOF_CHAIN.md` — the spec→machine-code chain and its two honest
  remaining trust gaps.

### 3.4 Honest boundary docs
- `SECURITY.md` — what is proved, assumed, and out of scope.

---

## 4. How to build & reproduce (for the auditor)

```bash
# Functional test suite (both compilers)
cd sml-tls && make test && make test-poly      # => 306 passed, 0 failed each

# FFI constant-time path (requires libsodium)
make test-ffi                                   # cross-impl byte-identity vs oracle

# Formal proofs (requires HOL4 + Poly/ML)
cd proof && Holmake cleanAll && Holmake         # => 5 theories OK

# Verified-compiler machine-code demo (requires cached cake binary)
bash cakeml/compile_chain_demo.sh               # => RESULT: PASS

# Differential / fuzz harnesses
cd ../sml-tls-tool && make
bash scripts/run_openssl_diff.sh
bash scripts/run_afl.sh
```

---

## 5. Known issues to flag to the auditor up front

1. **AES-GCM and RSA-PSS remain pure-SML and variable-time** (libsodium offers
   no portable constant-time AES-GCM/RSA). For an AES-GCM-only deployment with
   a timing adversary, these need FFI-izing.
2. **Memory zeroing is best-effort**: SML strings are immutable and the GC may
   have copied secrets; `zeroize` overwrites the currently-referenced buffers
   only (documented in `SECURITY.md`).
3. **Formal refinement gaps** (do not affect the running pure-SML/FFI library,
   relevant only to the "provably correct to machine code" claim): the Track 2c
   refinement is hand-mirrored (not yet `ml_translatorLib`-certified), and the
   CakeML `compile_correct` theorem is not yet instantiated in-logic for our
   programs (`proof/PROOF_CHAIN.md`, GAP A / GAP B).

---

## 6. Status

- [x] Track 1 complete (constant-time FFI, zeroing, PSK accept path) —
      audit prerequisite met.
- [x] Audit-readiness package prepared (this document + harnesses + docs).
- [ ] **External audit commissioned** — maintainer action: select and engage a
      reputable TLS/cryptography auditor (e.g. a firm experienced with protocol
      implementations) using this package as the scope-of-work.
- [ ] Findings triaged and remediated.

Until an external audit is commissioned and its findings addressed,
`sml-tls` must not be used to protect real secrets (see `SECURITY.md`).
