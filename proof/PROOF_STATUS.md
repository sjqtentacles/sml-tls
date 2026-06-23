# Proof status — HOL4 formal-verification track (B1 / J4)

This document records, honestly and precisely, what the HOL4 theories in
`proof/` actually establish, what they assume, and the gap between the HOL4
spec, the SML implementation (`lib/.../sml-tls/tls.sml`), and the CakeML port
(`cakeml/`).

## Build

`Holmake` builds `proof/` **clean** (verified from a `Holmake cleanAll` then
`Holmake`): all three theories compile and every `Theorem … QED` is closed by
a real proof. There are **no `cheat`s**, **no `new_axiom`s**, and **no custom
oracles**. A machine check of the built theories reports:

* `axioms("tls_wire")` = `axioms("tls_keyschedule")` = `axioms("tls_handshake")` = `0`
* the only oracle tag on any theorem is `DISK_THM` (the benign tag HOL4 puts
  on every theorem serialized to/from disk — it is **not** a trust oracle).

So every theorem listed as "proved" below is proved in the HOL4 kernel,
subject only to the explicitly-labeled assumptions in the section "Trusted
boundary".

## Status legend

* **proved** — closed by a real kernel proof with no extra assumptions.
* **proved (bound)** — proved, with an explicit, honest side condition on a
  length (the wire length fields impose these; real TLS bounds are tighter).
* **proved (modulo trusted primitive)** — proved, but its content depends on
  the abstract length-only contract of a trusted crypto primitive (see below).
* **not modeled** — intentionally **no** theorem is stated (a `cheat` here
  would assert a falsehood and make the theory inconsistent — see notes).

---

## `tls_wireTheory` — wire formats (RFC 8446 §4, §5)

Helper lemmas (all **proved**): `w16_of_to_bytes`, `w16_len_roundtrip`,
`w24_recon` (by bit-blasting), `n2w_mod256`, `len3_w24_roundtrip`,
`decodeExts_loop_correct`.

Round-trip theorems `decode (encode x) = SOME (x, …)`:

| theorem | status | side condition |
|---|---|---|
| `decode_encode_contentType` | **proved** | — |
| `decode_encode_handshakeType` | **proved** | — |
| `decode_encode_plaintext` | **proved (bound)** | `LENGTH fragment < 2^16` |
| `decode_encode_ciphertext` | **proved (bound)** | `LENGTH encryptedRecord < 2^16` |
| `decode_encode_message` | **proved (bound)** | `LENGTH body < 2^24` |
| `decode_encode_extensions` | **proved (bound)** | each `LENGTH data < 2^16` and total block `< 2^16` |
| `finished_roundtrip` | **proved (bound)** | `verifyData <> []` (matches SML, which rejects empty) |
| `certificateVerify_roundtrip` | **proved (bound)** | `LENGTH sigBytes < 2^16` |
| `decode_encode_newSessionTicket` | **proved (bound)** | `wfNewSessionTicket` (see below) |
| `decode_encode_certificate` | **proved (bound)** | `wfCertificate` (see below) |
| `decode_encode_serverHello` | **proved (bound)** | `wfServerHello` (see below) |
| `decode_encode_clientHello` | **proved (bound)** | `wfClientHello` (see below) |

The length side conditions are genuine: a 2-byte (resp. 3-byte) length field
cannot represent a value `>= 2^16` (resp. `2^24`), so the round-trip can only
hold under the bound. These are not weaknesses of the proof; they are facts
about the format. (TLS itself bounds records below `2^14`.)

### Now modeled: `newSessionTicket`, `certificate`, `serverHello`, `clientHello`

All four structures are now fully modeled with `encode<X>_def` / `decode<X>_def`
mirroring the SML (`tls.sml`) field order and framing, a well-formedness
predicate `wf<X>` capturing the on-the-wire length bounds, and a **proved**
round-trip `wf<X> x ==> decode<X> (encode<X> x) = SOME x` (no `cheat`, no
oracle beyond `DISK_THM`).

The nested length-prefixed lists are handled by generic combinators with their
own proved loop-correctness lemmas, layered on the existing framing lemmas:

* `decodeW16s_loop_correct` — parses a length-prefixed list of `word16`
  (cipher-suite list) back to the original list.
* `encodeW16ListBody_length` — the encoded suite body is `2 * LENGTH suites`.
* `decodeExtensionsR_correct` — a remainder-passing extension-block decoder
  (returns `(exts, rest)`), used inside the per-entry certificate loop.
* `decodeCertEntries_loop_correct` — parses the concatenation of encoded
  `CertificateEntry`s (each with its own 3-byte length prefix and nested
  extension block) back to the original list.

The exact well-formedness side conditions are:

* **`wfNewSessionTicket t`**: `LENGTH ticketNonce < 2^8`, `LENGTH ticket < 2^24`,
  each extension's `LENGTH data < 2^16`, and the encoded extension block
  `< 2^16`.
* **`wfCertificate c`**: `LENGTH certificateRequestContext < 2^8`,
  `LENGTH (encodeCertEntries certificateList) < 2^24`, and per entry:
  `LENGTH certData < 2^24`, each extension's `LENGTH data < 2^16`, and the
  encoded extension block `< 2^16`.
* **`wfServerHello sh`**: `LENGTH random = 32`, `LENGTH legacySessionId < 2^8`,
  each extension's `LENGTH data < 2^16`, and the encoded extension block
  `< 2^16`.
* **`wfClientHello ch`**: `LENGTH random = 32`, `LENGTH legacySessionId < 2^8`,
  `LENGTH cipherSuites < 2^15` (so the 2-byte byte-count `2*n` stays `< 2^16`),
  `LENGTH legacyCompression < 2^8`, each extension's `LENGTH data < 2^16`, and
  the encoded extension block `< 2^16`.

These bounds are genuine consequences of the wire length fields (1-, 2-, and
3-byte length prefixes), exactly in the honest-bound style of the simpler
codecs above. The HOL4 decoders always parse the trailing extension block via
`decodeExtensions` (matching the always-present length-prefixed block the
encoders emit), so the round-trip holds unconditionally given `wf<X>`.

---

## `tls_keyscheduleTheory` — key schedule (RFC 8446 §7.1, RFC 5869)

### Trusted abstract primitives

`sha256`, `hmac_sha256`, and `hkdfExpand` are introduced as **underspecified
constants** via `new_specification` (a *conservative*, sound extension — the
existence witnesses are constant-length functions, so **no axiom is added**).
Only their **output-length contracts** are specified:

* `sha256_length`     : `LENGTH (sha256 bs) = 32`
* `hmac_sha256_length`: `LENGTH (hmac_sha256 k d) = 32`
* `hkdfExpand_length` : `LENGTH (hkdfExpand prk info L) = L`

Their *values* are deliberately not pinned down, so nothing false about their
contents can be derived. **What is assumed and NOT proved:** that these
constants behave like real SHA-256 / HMAC-SHA-256 / HKDF-Expand, and in
particular their cryptographic strength (collision/preimage resistance, PRF
security). That is the crypto trust boundary.

`hkdfExtract`, `hkdfExpandLabel`, `deriveSecret`, the three Extract stages,
the traffic/finished keys and `finishedVerifyData` are **defined** exactly as
RFC 8446 §7.1 / RFC 5869 prescribe in terms of the primitives above.

### Theorems

Output-length correctness — all **proved (modulo trusted primitive)**:
`hkdfExtract_length`, `hkdfExpandLabel_length`, `deriveSecret_length`,
`earlySecret_length`, `handshakeSecret_length`, `masterSecret_length`,
`trafficKey_length`, `trafficIv_length`, `finishedKey_length`,
`finishedVerifyData_length`.

Structural correctness — **proved**:
* `schedule_correct` — the 1-RTT `schedule` bundle wires its fields exactly as
  the staged RFC Extract → Derive → Extract chaining prescribes.
* `schedule_lengths` — every secret in the bundle has the SHA-256 length.

### Not included: RFC 8448 test vectors

The original script `cheat`-ed three theorems asserting that the schedule
equals the published RFC 8448 hex vectors. Those are **removed**: with abstract
(value-free) primitives they are not provable, and the previous stubs
(`sha256 = zeros`, `hex_to_word8 = []`) made the equalities *false*, so a
`cheat` was unsound. Discharging the RFC 8448 vectors requires linking
`sha256`/`hmac` to a concrete, verified bit-level implementation (e.g. a
verified SHA-256 from the CakeML tower) and `EVAL`-ing against it. That is the
intended future refinement and is tracked open work.

---

## `tls_handshakeTheory` — handshake state machine (RFC 8446 §7.1)

Single-transition structural facts — **proved** for all states:
* `transcript_append_only` — a transition never shrinks the transcript.
* `idle_only_clientHello` — the only transition that leaves `CIdle` for the
  handshake proper is `SendClientHello` (restated precisely: close-notify can
  also fire from any state).
* `closed_is_absorbing` — a closed client only goes to `CClosed` or nowhere.

Reachability + inductive safety invariants:
* `reachable` — inductive predicate: states reachable from a fresh endpoint.
* `reachable_no_keys` — **proved**: `keysInstalled` is never set, so it is
  false on every reachable state.
* `reachable_safety` — **proved** (core invariant, by rule induction): any
  reachable endpoint sitting in a post-Finished state
  (`CServerFinishedReceived`/`CClientFinishedSent`/`CConnected` for the client,
  `SClientFinishedReceived`/`SConnected` for the server) has
  `peerFinishedVerified = T`.
* `connected_implies_finished` — **proved**: no reachable endpoint is
  `Connected` without a verified peer Finished.
* `client_no_appData_before_finished` — **proved**: a reachable *client* cannot
  send application data before the server's Finished is verified.
* `keys_after_secret` — **proved**, but **vacuously** (keys are never installed
  in this abstract model).

### Honest caveats on the handshake model

* The four single-transition "safety" theorems as originally stated
  (`no_appData_before_finished`, `connected_implies_finished`,
  `keys_after_secret` over arbitrary states, and `idle_only_clientHello` as an
  iff) were **false for hand-crafted non-reachable records** and were
  `cheat`-ed. They are replaced by the genuinely-true statements above
  (inductive invariants over `reachable`, or precise restatements).
* The application-data-before-Finished guarantee is proved for the **client
  only**. The server side of this model overloads `SendApplicationData` as the
  trigger for the entire server flight
  (`SServerHelloSent --SendApplicationData--> SServerFinishedSent`), so the
  unconditional server statement is *false in this model*. This is a modeling
  shortcut, recorded here rather than hidden behind a `cheat`.
* `keysInstalled` is a vestigial field: key installation is **not** modeled.
* `eventBytes` is a placeholder (`= []`), so the transcript is modeled
  abstractly; transcript *content* (and thus real transcript-hash binding) is
  not modeled.

---

## Trusted boundary (summary)

The HOL4 theorems above rely on **no axioms** and **no proof oracles**. The
genuine trust assumptions are:

1. **Cryptographic primitives.** `sha256`, `hmac_sha256`, `hkdfExpand` are
   abstract, specified only by output length. Their cryptographic security
   (collision resistance of SHA-256, PRF/HMAC security, etc.) and the
   correctness of AES-GCM / ChaCha20-Poly1305 / X25519 are **assumed, not
   proved**. None of these is mechanized here.
2. **Length-bound side conditions** on the wire round-trips (listed per
   theorem). These are honest consequences of the on-the-wire length fields.

## Spec ↔ implementation gap (HOL spec vs SML vs CakeML)

There is **no mechanized refinement proof** linking the HOL4 spec to the SML
(`tls.sml`) or the CakeML port. Concretely:

* The HOL4 wire codecs are an *independent re-modeling* of RFC 8446, aligned
  with `tls.sml` **by manual inspection** of field order and framing. They are
  not proved equal to the SML functions, and there is no CakeML
  translator/extraction theorem connecting either to running code.
* `clientHello` / `serverHello` / `certificate` / `newSessionTicket` codecs are
  now modeled in HOL4 with proved round-trips (under `wf<X>` bounds), but they
  are still an *independent re-modeling* aligned with `tls.sml` by inspection —
  not proved equal to the SML functions.
* The key schedule matches the RFC *structurally*; it is not validated against
  the RFC 8448 byte vectors (needs concrete crypto), and is not proved to match
  the SML `TlsKeySchedule` module.
* The handshake theory is an *abstract* state machine. It captures ordering and
  the Finished-before-Connected/AppData safety property, but does not model
  message contents, key installation, or the full server-flight granularity,
  and is not refined to the SML `tlsstate.sml` driver.

In short: the claim supported by these proofs is **"the modeled RFC 8446 wire
round-trips hold (under stated length bounds), the key-schedule construction is
structurally the RFC 8446 §7.1 schedule with correct output lengths, and the
abstract handshake automaton never reaches Connected / emits client
application data without a verified peer Finished."** It is **not** a claim that
the SML or CakeML code is correct, nor that the underlying cryptography is
secure.
