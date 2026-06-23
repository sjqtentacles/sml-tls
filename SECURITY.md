# Security and correctness boundary — sml-tls

This document describes precisely what security and correctness properties
`sml-tls` establishes, what it assumes, and what remains out of scope.  It is
intended to be honest and non-overstated.

---

## What has been built and verified

### Functional completeness (pure SML, both MLton + Poly/ML)

A full TLS 1.3 (RFC 8446) client and server state machine in pure Standard ML:

- **Record layer** (RFC 8446 §5): `TLSPlaintext` / `TLSCiphertext` encode/decode,
  `record_overflow` enforcement, streaming fraining.
- **Alert protocol** (§6): all RFC 8446 alert codes, correct wire bytes,
  round-trip tested.
- **Handshake messages** (§4): ClientHello, ServerHello, HelloRetryRequest,
  EncryptedExtensions, Certificate, CertificateVerify, Finished,
  NewSessionTicket — encode/decode against the RFC 8446 wire format.
- **Extensions** (§4.2): key_share, supported_versions, supported_groups,
  signature_algorithms, SNI, ALPN, cookie, pre_shared_key,
  psk_key_exchange_modes, early_data — codecs + negotiation helpers.
- **Key schedule** (§7.1): full HKDF-based 1-RTT schedule, verified byte-for-byte
  against RFC 8448 published test vectors.
- **AEAD record protection** (§5.2): AES-128-GCM / AES-256-GCM /
  ChaCha20-Poly1305 via vendored `sml-aead`, with nonce construction and
  sequence-number threading.
- **Certificate chain validation**: X.509 chain traversal, RSA signature
  verification on each link, basic-constraints/path-length, hostname matching,
  validity window.
- **CertificateVerify** (§4.4.3): RSA-PSS-SHA256 signing (server) and
  verification (client), with the correct RFC 8446 `0x00`-separated signed
  content and `signature_algorithms` enforcement.
- **Handshake features**: full 1-RTT, HelloRetryRequest + cookie (with the
  §4.4.1 synthetic transcript-hash substitution), 0-RTT/early_data reject,
  PSK key-schedule primitives + explicit server-side PSK reject.
- **Post-handshake**: KeyUpdate (§4.6.3, §7.2) with traffic-key ratchet;
  NewSessionTicket issuance.
- **Alerts and robustness**: every error path raises a fatal alert.  A
  catch-all backstop maps any unexpected exception to `decode_error`, so
  untrusted input cannot crash `step`.

**Test coverage:** 306 passing tests on both MLton and Poly/ML, including RFC
8448 vector tests, round-trip tests, negative / tamper tests, PSK-resumption
accept + negative-binder tests, FFI cross-implementation byte-equality tests,
and key-zeroization tests.

### Interoperability (J2)

A live OpenSSL 3.6.0 differential (`openssl s_server` ↔ the pure-SML client
via a socket shim) confirmed a full TLS 1.3 handshake completes:
X25519 + AES-128-GCM, real RSA-2048 certificate parsed, chain + hostname +
validity verified, RSA-PSS `CertificateVerify` verified, server Finished MAC
verified → **CONNECTED**.

Six real interoperability bugs were discovered and fixed by this differential
(alert wire codes, certificate/CV field lengths, Finished handshake type, and
coalesced server-flight draining), each captured by a regression test.

An AFL fuzz harness (33 000+ random inputs) ran crash-free on the parser
entry points.

### CakeML port (L0–L4)

The entire stack — the crypto tower (sha256, bigint, aes, chacha20, x25519,
asn1, pem, aead, kdf, rsa, x509) plus the TLS protocol logic — is ported to
the CakeML dialect and verified for real on the pinned v3400 CakeML compiler
(prebuilt bootstrapped `cake-arm8-64`, 2026-06-18, native arm64).  An
in-process client↔server 1-RTT handshake runs under CakeML: both sides reach
CONNECTED, with the server's RSA-PSS CertificateVerify and Finished verified
by the client.

Because the CakeML *compiler* (not just the runtime) is formally verified, the
CakeML-compiled binary's operational behavior is backed by a proof chain from
HOL4 semantics to machine code — **provided** the source program is also
verified (see "What is not proved" below).

### HOL4 formal proofs (`proof/`)

`proof/` builds cleanly under HOL4 Trindemossen 2 (`Holmake cleanAll &&
Holmake` → all **five** theories OK: `tls_sha256`, `tls_wire`,
`tls_keyschedule`, `tls_handshake`, `tls_refinement`).  Machine check: 0
axioms, 0 custom oracles, 0 cheats.  See
[`proof/PROOF_STATUS.md`](proof/PROOF_STATUS.md) for theorem-by-theorem detail
and [`proof/PROOF_CHAIN.md`](proof/PROOF_CHAIN.md) for the spec→machine-code
chain.

**What is genuinely proved:**

- **Wire round-trips** (RFC 8446 §4, §5): `decode(encode x) = SOME(x, …)` for
  all record/framing structures (TLSPlaintext, TLSCiphertext, handshake
  framing, extension framing, Finished, CertificateVerify) **and all four
  structured hello/cert/ticket codecs** (ClientHello, ServerHello, Certificate,
  NewSessionTicket), each under the honest length-bound side conditions imposed
  by the wire length fields.
- **Concrete key schedule** (RFC 8446 §7.1): `sha256`/`hmac`/`hkdf` are
  concrete, computable HOL4 definitions (FIPS 180-4 / RFC 2104 / RFC 5869);
  two RFC 8448 key-schedule vectors are discharged by computation (no cheats),
  and the `schedule` bundle is proved to wire its fields exactly per the staged
  Extract → Derive → Extract chaining, with correct output lengths.
- **Handshake safety invariants** (8 theorems): transcript append-only;
  ClientHello is the only first transition; Closed is absorbing; core inductive
  safety invariant over reachable states; `Connected` implies peer Finished was
  verified; client emits no application data before the server Finished is
  verified; keys are never installed in the abstract model.
- **CakeML ↔ spec refinement** (Track 2c): HOL4 functions mirroring the CakeML
  codecs (contentType, plaintext, ciphertext) are proved equal to the spec
  codecs, and a control-phase fragment of the state machine is proved to refine
  the handshake automaton. (Hand-mirrored, not yet `ml_translatorLib`-certified
  — see gaps below.)

---

## What is NOT proved (the honest trust boundary)

### 1. Cryptographic security

The cryptographic primitives — SHA-256, HMAC-SHA-256, HKDF, AES-GCM,
ChaCha20-Poly1305, X25519, RSA-PSS — are **trusted black boxes**.  Their
correctness relative to the published standards is checked empirically (RFC
vector tests and OpenSSL differential), **not proved**.  Their security
properties (collision resistance, PRF/HMAC security, IND-CCA2 of the AEAD
schemes, CDH hardness of X25519, etc.) are **assumed, not derived**.

The HOL4 key-schedule theorems model `sha256` / `hmac_sha256` / `hkdfExpand`
as abstract constants specified only by output length.  Nothing about their
values is proved.

### 2. Constant-time execution (addressed in the FFI build)

Pure Standard ML arithmetic is **not constant-time**.  To address this,
`sml-crypto-ffi` routes the high-value primitives through audited,
constant-time C libraries via MLton `_import` / Poly/ML `Foreign`, with
cross-implementation tests asserting byte-identical (or, for randomized PSS,
cross-verifying) output against the pure-SML oracles:

- **X25519 and ChaCha20-Poly1305** → **libsodium** (constant-time, audited).
- **AES-128/256-GCM and RSA-PSS-SHA256** → **OpenSSL libcrypto 3.x**
  (`EVP_aes_*_gcm`, `EVP_DigestSign/Verify` with `RSA_PKCS1_PSS_PADDING`),
  which are constant-time with respect to secret material.  libsodium offers
  no portable AES-128-GCM or RSA, which is why OpenSSL backs these two.

The **FFI build** (`make test-ffi` / `make test-ffi-poly`, selecting
`sources-ffi.mlb`) routes the live handshake through these constant-time
backends: AES-GCM record protection (via the `aead_ffi` AEAD facade), the
RSA-PSS `CertificateVerify` and X.509 RSASSA-PSS signature checks (via an
OpenSSL backend installed over `Rsa.signPss`/`verifyPss`), and key zeroing
(`sodium_memzero`).  Byte-identity against NIST GCM vectors and pure↔OpenSSL
RSA-PSS cross-verification are proved in `test/ffi.sml` on both compilers.

**Residual risk:** the **default** (no-FFI) build is still 100% pure-SML and
variable-time across all primitives; it is retained as the portable build and
as the proof oracle.  Deployments needing constant-time execution must use the
FFI build.  OpenSSL's and libsodium's own constant-timeness is trusted
(audited upstream), the same trust posture applied to all FFI primitives.

### 3. Mechanized refinement from spec to code (partially addressed)

The HOL4 theories are an independent RFC re-model.  Track 2c adds a **proved**
refinement that HOL4 functions mirroring the CakeML codecs (contentType,
plaintext, ciphertext) **equal** the spec codecs, plus a control-phase
state-machine fragment refining the handshake automaton.  **Remaining gaps**
(see [`proof/PROOF_CHAIN.md`](proof/PROOF_CHAIN.md)): the mirrors are
hand-proved, not yet `ml_translatorLib`-certified against the actual CakeML
AST (GAP A); and the CakeML `compile_correct` backend theorem is not yet
instantiated in-logic for our programs — we trust the verified `cake` binary
to compile faithfully rather than an in-logic `compile` evaluation (GAP B).
The remaining hello/cert/ticket codecs and the full crypto-bearing
mid-handshake simulation are not yet refined.

### 4. Memory zeroing (partially addressed, best-effort)

`TlsClient.zeroize` / `TlsServer.zeroize` / `zeroizeConfig` overwrite traffic
keys, derived secrets, and `serverConfig.rsaPrivateKeyDer` via `sodium_memzero`
(an FFI call the optimizer cannot elide).  **Best-effort caveat:** SML strings
are immutable and the GC may have copied secrets before zeroization; only the
currently-referenced buffers are overwritten, so prior copies may survive.

### 5. No audit

This library has had no external security audit.  The audit-readiness package
and scope-of-work are prepared in [`AUDIT.md`](AUDIT.md); commissioning the
audit is the remaining gate before any real-secret deployment.

---

## What it is suitable for

- Reference implementation and educational study of TLS 1.3.
- Testing and fuzzing other TLS implementations (via `sml-tls-tool`).
- Automated RFC conformance verification (the 280-test suite and AFL harnesses
  cover the majority of the RFC's normative requirements).
- Formal-methods research: extending the HOL4 spec toward a full mechanized
  refinement, or using the CakeML port as the target of `ml_translatorLib`
  extraction.

---

## What it is NOT suitable for

- Protecting real secrets or sensitive communications.
- Any deployment where a network adversary is present.
- Any context where timing side-channel resistance is required.
- Drop-in replacement for a production TLS library (OpenSSL, BoringSSL,
  rustls, etc.).

---

## Progress toward production security

Completed (see `AUDIT.md`, `proof/PROOF_STATUS.md`, `proof/PROOF_CHAIN.md`):

1. ✅ **Model the four remaining codecs** in HOL4 (ClientHello, ServerHello,
   Certificate, NewSessionTicket) with well-formedness side conditions — round
   trips proved.
2. ✅ **Concrete verified SHA-256** in HOL4; RFC 8448 key-schedule vectors
   discharged by computation.
3. ✅ **Mechanized refinement** (partial): CakeML-shaped codecs proved equal to
   the HOL4 spec; control-phase state-machine fragment refined.
4. ✅ **Spec→machine-code chain** demonstrated end-to-end with the verified
   CakeML compiler; formal chain documented with explicit remaining gaps.
5. ✅ **Constant-time crypto** (FFI build): X25519 + ChaCha20-Poly1305 via
   libsodium; AES-128/256-GCM + RSA-PSS-SHA256 via OpenSSL libcrypto, with the
   live handshake routed through them in the `sources-ffi.mlb` build.
6. ✅ **Memory zeroing**: `zeroize` API via `sodium_memzero` (best-effort).
7. ✅ **PSK resumption (accept path)**: server ticket store, binder
   verification, PSK key schedule.

Remaining:

- Full `ml_translatorLib` certification of the refinement (GAP A) and in-logic
  instantiation of `compile_correct` (GAP B) — `proof/PROOF_CHAIN.md`.
- Extend refinement to the remaining codecs and the full crypto-bearing
  handshake simulation.
- **Commission the external security audit** (`AUDIT.md`) and remediate
  findings — the final gate before any real-secret deployment.
