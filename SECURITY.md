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

**Test coverage:** 280 passing tests on both MLton and Poly/ML, including RFC
8448 vector tests, round-trip tests, and negative / tamper tests throughout.

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
Holmake` → all three theories OK).  Machine check: 0 axioms, 0 custom oracles.
See [`proof/PROOF_STATUS.md`](proof/PROOF_STATUS.md) for theorem-by-theorem
detail.

**What is genuinely proved:**

- **Wire round-trips** (RFC 8446 §4, §5): `decode(encode x) = SOME(x, …)` for
  all concrete record/framing structures (TLSPlaintext, TLSCiphertext,
  handshake framing, extension framing, Finished, CertificateVerify), under the
  honest length-bound side conditions imposed by the wire length fields.
- **Key-schedule structure** (RFC 8446 §7.1): the `schedule` bundle wires its
  fields exactly as the staged Extract → Derive → Extract chaining prescribes;
  all output lengths are correct (modulo the abstract primitive contract below).
- **Handshake safety invariants** (8 theorems): transcript append-only;
  ClientHello is the only first transition; Closed is absorbing; core inductive
  safety invariant over reachable states; `Connected` implies peer Finished was
  verified; client emits no application data before the server Finished is
  verified; keys are never installed in the abstract model.

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

### 2. Constant-time execution

Pure Standard ML arithmetic is **not constant-time**.  Every conditional
branch and table lookup in the RSA, AES, X25519, and ChaCha20 implementations
can leak information through execution time and cache behavior.  An adversary
sharing a CPU with this code can, in principle, recover private key material
through timing side channels.  This is inherent to the language/runtime and
cannot be fixed without leaving pure SML (e.g., assembly or hardware-backed
cryptography via C FFI).  Do not use this library where a timing adversary is
present.

### 3. No mechanized refinement from spec to code

The HOL4 theories are an **independent RFC re-model**, aligned with `tls.sml`
by manual inspection of field order and framing.  There is **no mechanized
proof** that the SML functions implement the HOL4 spec, and no
CakeML-translator/extraction theorem connecting either to the running binary.

Specifically:
- The HOL4 wire codecs are not proved equal to the SML encoder/decoder
  functions.
- The HOL4 key-schedule definition is not validated against the RFC 8448 byte
  vectors (requires a concrete, verified SHA-256 plugged in — open work).
- The HOL4 handshake automaton is **abstract**: message contents, key
  installation, and full server-flight granularity are not modeled.  It is not
  refined to `tlsstate.sml`.
- Four message codecs (`clientHello`, `serverHello`, `certificate`,
  `newSessionTicket`) are **not modeled** in HOL4 (their structured, nested,
  length-prefixed encoding does not admit a simple unconditional round-trip
  theorem without significant additional proof work).

### 4. No memory zeroing

Secret key material (traffic keys, private keys passed in `serverConfig`) lives
on the SML heap and is subject to GC movement and eventual serialization
without explicit zeroing.  There is no guarantee that secrets are erased from
memory after use.

### 5. No audit

This library has had no external security audit.

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

## Open work toward production security

In approximate dependency order:

1. **Mechanized refinement**: prove the SML implementation implements the HOL4
   spec (wire codecs via a `decode ∘ encode = id` approach with formally
   verified combinator parsers; key schedule by `EVAL` with a concrete verified
   SHA-256).
2. **Model the four remaining codecs** in HOL4 (ClientHello, ServerHello,
   Certificate, NewSessionTicket) with appropriate well-formedness side
   conditions.
3. **Concrete verified SHA-256**: link the HOL4 key-schedule spec to the
   verified CakeML SHA-256 implementation via `ml_translatorLib`, discharging
   the RFC 8448 vector theorems.
4. **CakeML translator proof** (J4 full): compile the TLS code via
   `ml_translatorLib` to get HOL4 theorems connecting the SML source to the
   CakeML semantics, then use the CakeML compiler's proof to close the chain
   to machine code.
5. **Constant-time crypto**: replace the pure-SML arithmetic in the crypto
   primitives with C FFI calls to a verified or audited constant-time
   implementation (e.g. libsodium, HACL*).
6. **Memory zeroing**: add an explicit key-erasure API and implement it via
   FFI.
7. **PSK resumption** (accept path): implement the full server-side PSK accept
   flow (ticket storage, binder verification, 0-RTT key install) on top of the
   currently implemented key-schedule and binder primitives.
