# Proof status — HOL4 formal-verification track (B1 / J4)

This document records, honestly and precisely, what the HOL4 theories in
`proof/` actually establish, what they assume, and the gap between the HOL4
spec, the SML implementation (`lib/.../sml-tls/tls.sml`), and the CakeML port
(`cakeml/`).

## Build

`Holmake` builds `proof/` **clean** (verified from a `Holmake cleanAll` then
`Holmake`): all **five** theories compile and every `Theorem … QED` is closed
by a real proof. There are **no `cheat`s**, **no `new_axiom`s**, and **no
custom oracles**. A machine check of the built theories reports:

* `axioms("tls_wire")` = `axioms("tls_keyschedule")` = `axioms("tls_handshake")` = `axioms("tls_sha256")` = `axioms("tls_refinement")` = `0`
* the only oracle tag on any theorem is `DISK_THM` (the benign tag HOL4 puts
  on every theorem serialized to/from disk — it is **not** a trust oracle).
  Every theorem in `tls_refinementTheory` carries only `DISK_THM`.

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

### Concrete primitives (Track 2b)

`sha256`, `hmac_sha256`, and `hkdfExpand` are now **concrete, computable
`Definition`s**, backed by `tls_sha256Theory` — an independent FIPS 180-4 /
RFC 2104 / RFC 5869 HOL4 implementation (SHA-256 compression over native
`word32`, HMAC-SHA-256, and HKDF-Extract/Expand). They are ordinary
definitions, so they add **no axiom and no oracle**; their values are pinned
down and reducible by `EVAL`.

Their **output-length contracts** are still proved:

* `sha256_length`     : `LENGTH (sha256 bs) = 32`
* `hmac_sha256_length`: `LENGTH (hmac_sha256 k d) = 32`
* `hkdfExpand_length` : `LENGTH (hkdfExpand prk info L) = L`

**What is still assumed and NOT proved:** (1) the *cryptographic strength* of
SHA-256/HMAC (collision/preimage resistance, PRF security) — that is an
inherent trust boundary, not a provable property; and (2) that
`tls_sha256$sha256_digest` is provably **equal** to the CakeML `cakeml/sha256.sml`
source — it is structurally aligned (same K constants, init vector, padding,
schedule, compression) but the `ml_translatorLib` equality link is Track 2c.

`hkdfExtract`, `hkdfExpandLabel`, `deriveSecret`, the three Extract stages,
the traffic/finished keys and `finishedVerifyData` are **defined** exactly as
RFC 8446 §7.1 / RFC 5869 prescribe in terms of the primitives above.

### Theorems

Output-length correctness — all **proved**:
`hkdfExtract_length`, `hkdfExpandLabel_length`, `deriveSecret_length`,
`earlySecret_length`, `handshakeSecret_length`, `masterSecret_length`,
`trafficKey_length`, `trafficIv_length`, `finishedKey_length`,
`finishedVerifyData_length`.

Structural correctness — **proved**:
* `schedule_correct` — the 1-RTT `schedule` bundle wires its fields exactly as
  the staged RFC Extract → Derive → Extract chaining prescribes.
* `schedule_lengths` — every secret in the bundle has the SHA-256 length.

### RFC 8448 test vectors — now discharged by computation (Track 2b)

Two RFC 8448 ("Example Handshake Traces for TLS 1.3") key-schedule vectors are
now **proved by `EVAL`** against the concrete SHA-256, with **no `cheat`**:

* `rfc8448_early_secret`   — `earlySecret zeros` = the published 32-byte Early
  Secret `HKDF-Extract(0_32, 0_32)`.
* `rfc8448_derived_secret` — `deriveSecret (earlySecret zeros) "derived" []` =
  the published 32-byte derived-for-handshake secret.

These are closed by a tuned `computeLib` compset (`wordsLib` fast word
conversions + the SHA-256/HMAC/HKDF/key-schedule equations) followed by a
final `EVAL` to decide the literal equality. Bare `EVAL` alone does not finish
on the 64-round SHA-256 core; the fast compset reduces it in seconds. Both
theorems carry only the benign `DISK_THM` tag (no oracle). Vectors that depend
on a full transcript hash (handshake/master/application secrets) still require
the transcript bytes and are tracked as remaining work alongside Track 2c.

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

---

## `tls_refinementTheory` — CakeML ↔ HOL spec refinement (Track 2c)

This theory mechanizes the link between the CakeML implementation
(`cakeml/tls.sml`, `cakeml/tls_state.sml`) and the HOL4 wire/handshake specs.
It builds clean with **`axioms("tls_refinement") = 0`**, no `cheat`, and only
the benign `DISK_THM` tag.

### Method and its honest limitation (hand-mirror, not yet `ml_translatorLib`)

The CakeML port and the HOL4 spec model the **same** RFC 8446 codecs in two
surface representations: the spec uses records over `word8 list` / `word16`
with HOL word arithmetic, while CakeML (no records, no `Word16/Word32`) uses
tuples, native-`int` bytes (de)serialized by `div`/`mod` and `*256+`, and
`string`s of 0..255 chars. This theory **mirrors the CakeML codec functions by
hand in HOL4** — same tuple shapes, same `div`/`mod` arithmetic, same length
guards — over a faithful representation of the CakeML value space
(a CakeML byte `int` = a HOL `num`; a CakeML `string` = a HOL `num list`;
`String.size`=`LENGTH`, `String.sub`=`EL`, `String.substring`=`TAKE∘DROP`,
`String.extract _ None`=`DROP`, `^`=`++`, `Char.ord/Char.chr`=identity on
0..255), and proves these mirrors **equal** the spec codecs transported across
the byte-representation map `b2n = w2n` / `s2ns = MAP w2n`.

**Translator-certification gap (remaining 2c work).** These equalities are
proved against a hand-written HOL mirror of `cakeml/tls.sml`, **not** against
an `ml_translatorLib`-certified deep embedding of the actual CakeML AST.
Integrating the full CakeML translator build (which deep-embeds the source and
emits a certificate relating the HOL function to the CakeML semantics) is heavy
(it previously caused resource exhaustion and was deliberately not rebuilt this
session). The link "the HOL mirror is *the* function `ml_translatorLib`
extracts from `cakeml/tls.sml`" is the **only** unfilled step of 2c. The
mathematically substantive half — that the CakeML-shaped arithmetic/control-flow
codec computes exactly the spec codec — **is** proved.

### Codec refinement theorems — all **proved** (hand-mirrored)

Representation map: `b2n_def` (`w2n`), `s2ns_def` (`MAP w2n`). Arithmetic-core
lemmas (**proved**): `w16_split_refines` (the CakeML `n div 256` / `n mod 256`
byte split equals the spec word-based hi/lo split, for `n < 2^16`),
`w16_read_refines` (the CakeML `hi*256+lo` read equals the spec
`w2n (w16_of_bytes hi lo)`, all bytes), `w2n_eq_small`. Structured-codec
helper lemmas (**proved**): `cml_word16ToBytes_refines`,
`cml_word32ToBytes_refines`, `cml_len3_refines`, `cml_encodeExtensions_refines`
(with `cml_encodeExtensionBody_refines` / `..._list_refines`),
`cml_encodeWord16List_refines` (with `cml_encodeWord16ListBody_refines`).

| codec | theorem | status |
|---|---|---|
| `contentType` encode | `cml_contentTypeToByte_refines` | **proved** |
| `contentType` decode | `cml_byteToContentType_refines` | **proved** |
| `plaintext` encode | `cml_encodePlaintext_refines` | **proved (bound `< 2^16`)** |
| `plaintext` decode | `cml_decodePlaintext_refines` | **proved** (all inputs) |
| `ciphertext` encode | `cml_encodeCiphertext_refines` | **proved (bound `< 2^16`)** |
| `ciphertext` decode | `cml_decodeCiphertext_refines` | **proved** (all inputs) |
| `serverHello` encode | `cml_encodeServerHello_refines` | **proved (`wfServerHello`)** |
| `clientHello` encode | `cml_encodeClientHello_refines` | **proved (`wfClientHello`)** |
| `newSessionTicket` encode | `cml_encodeNewSessionTicket_refines` | **proved (`wfNewSessionTicket`)** |
| `certificate` encode | `cml_encodeCertificate_refines` | **proved (`wfCertificate`)** |

Each `cml_*` function is the hand-mirror of the identically-named
`cakeml/tls.sml` function. The encode theorems have the honest length side
conditions (the 1-/2-/3-/4-byte wire length fields, exactly as in Track 2a:
the `wf<X>` predicates are the *same* well-formedness predicates the Track 2a
round-trips use). Because these mirrors are proved **equal** to the spec
codecs, the Track 2a round-trip theorems
(`decode_encode_plaintext`/`_ciphertext`/`_contentType`/`_serverHello`/
`_clientHello`/`_newSessionTicket`/`_certificate`) transfer to the
CakeML-shaped functions.

#### Newly added this pass (Track 2c expansion)

* **`cml_decodeCiphertext_refines`** — closes the prior hole where
  `cml_decodeCiphertext` was defined but had no refinement theorem. It mirrors
  `cml_decodePlaintext_refines` (the CakeML framing is byte-identical;
  `decodeCiphertext = decodePlaintext` in `cakeml/tls.sml`) and is proved for
  **all** inputs (no side condition).
* **Structured-codec ENCODE refinements** for `serverHello`, `clientHello`,
  `newSessionTicket`, and `certificate`. Each defines a CakeML-shaped
  `cml_encode<X>` (tuple-shaped, native-`int` length arithmetic, `String.str`/
  `^`/`String.concat` mirrored as `::`/`++`/`FLAT`), a per-codec representation
  map (`reprServerHello`/`reprClientHello`/`reprNewSessionTicket`/
  `reprCertificate`, plus `reprExt`/`reprCertEntry`), and proves
  `cml_encode<X> (repr<X> r) = s2ns (encode<X> r)` under the **same**
  `wf<X>` side condition Track 2a uses. The certificate proof uses an inner
  induction (`cml_encodeCertEntries_refines`) mirroring the SML `List.map
  oneEntry` over the certificate list.
* **Encode/decode composition corollaries** — `cml_serverHello_roundtrip_via_spec`,
  `cml_clientHello_roundtrip_via_spec`, `cml_newSessionTicket_roundtrip_via_spec`,
  `cml_certificate_roundtrip_via_spec`. Each composes the encode refinement with
  the Track 2a round-trip to state, soundly: *there is a spec wire string `bs`
  (namely `encode<X> r`) such that the CakeML encoder output is `s2ns bs` and the
  spec decoder recovers `r` from `bs`*. Since `s2ns = MAP w2n` is injective on
  byte lists, this pins the CakeML encoder output to a wire string the spec
  decoder inverts.

#### Honest partial-coverage note on the structured DECODE direction

For `serverHello`/`clientHello`/`newSessionTicket`/`certificate` the **decode**
direction is **not** refined as a standalone CakeML-shaped equational theorem.
The CakeML decoders (`decodeClientHello` etc. in `cakeml/tls.sml`) are
recursive, **exception-driven** byte parsers: they raise/catch a `Bad`
exception, re-read fields by absolute index via `String.sub`/`String.substring`,
derive the cipher-suite count as `csTotal div 2`, and lean on self-describing
extension blocks. Faithfully mirroring that control flow (a `Bad` option monad
plus the index arithmetic) and proving its equational refinement is materially
heavier than the encode side. Rather than discharge it unsoundly, the decode
side is covered **soundly but indirectly** by the composition corollaries above
(the spec decoder inverts the exact wire bytes the CakeML encoder emits) and is
recorded here as the remaining honest gap for these four structured codecs. The
simpler `plaintext`/`ciphertext` decoders **are** refined directly and
unconditionally.

### State-machine refinement — **partial fragment proved**, full simulation = 2d

The full CakeML `TlsClient.step` (`cakeml/tls_state.sml`) is an
exception-driven, crypto-bearing byte processor (decrypts flights, runs
X25519 / AEAD / the key schedule, parses every handshake message, threads a
15-field state tuple). The `tls_handshakeTheory` automaton is an **abstract**
event-labeled FSM with no message contents and no keys. A full simulation
between them requires modeling the entire crypto stack and is the
"months, not weeks" Track 2d frontier work — **not** attempted here.

What **is** proved is the **control-phase abstraction**: the dispatcher at the
top of `TlsClient.step` branches purely on three control flags of the state
tuple (`errorAlert` set?, `cipherSuiteOpt` set?, `connected`). We model exactly
those flags (`cmlClientCtrl`), define `cmlClientAbs` mapping them to the
abstract automaton's client phase, and prove (all **proved**, no `cheat`):

* `cml_startHandshake_refines_transition` — the client state built by
  `TlsClient.startHandshake` (`errorAlert=None`, `cipherSuiteOpt=None`,
  `connected=False`) abstracts to exactly the abstract automaton's
  post-`SendClientHello` state: `client_transition CIdle SendClientHello =
  SOME (cmlClientAbs cmlStartHandshakeCtrl)`. The **first** handshake
  transition is faithfully refined.
* `cml_errored_abs_closed` / `cml_closed_refines_transition` — any CakeML
  client with `errorAlert` set abstracts to `CClosed`, matching the
  dispatcher's error/teardown branch and `client_transition _ SendCloseNotify
  = SOME CClosed`.
* `cml_connected_abs` / `cml_connected_refines_idle` — a non-errored, connected
  CakeML client abstracts to `CConnected`, on which the automaton idles under
  application data (`client_transition CConnected SendApplicationData =
  SOME CConnected`).

This is a **real, sound refinement of the dispatcher's control phases and of
the initial ClientHello transition** — it is explicitly **not** a full
simulation of the mid-handshake transitions, which depend on the crypto stack
and are Track 2d.

### What remains for full 2c and for 2d

* **Full 2c (translator certification).** Replace the hand-mirrored `cml_*`
  codec definitions with `ml_translatorLib`-extracted deep embeddings of
  `cakeml/tls.sml` and prove the mirrors are exactly those extractions, closing
  the "hand-mirror vs certified-extraction" gap noted above. The refined-codec
  set now covers `contentType`/`plaintext`/`ciphertext` (encode **and** decode)
  plus the **encode** direction of `clientHello`/`serverHello`/`certificate`/
  `newSessionTicket` (their CakeML shapes diverge more from the spec — tuples,
  native-`int` length arithmetic, omitted record framing — so each carries its
  own representation map and `wf<X>` side condition). The remaining direct work
  for these four is the **decode** direction (their CakeML decoders are
  recursive, `Bad`-exception-driven, index-based parsers — see the honest
  partial-coverage note above); it is covered soundly-but-indirectly today via
  the `cml_*_roundtrip_via_spec` composition corollaries.
* **2d (state-machine simulation).** Model the CakeML crypto stack (X25519,
  AEAD, key schedule, transcript hashing) and the mid-handshake `step`
  transitions, and discharge a full forward simulation between `TlsClient.step`
  / `TlsServer.step` and the (suitably enriched) `transition` automaton,
  including message-content and key-installation modeling currently abstracted
  away in `tls_handshakeTheory`.

---

## Trusted boundary (summary)
The HOL4 theorems above rely on **no axioms** and **no proof oracles**. The
genuine trust assumptions are:

1. **Cryptographic primitives.** `sha256`, `hmac_sha256`, `hkdfExpand` are now
   **concrete, computable** HOL4 definitions (`tls_sha256Theory`), so the key
   schedule reduces to actual bytes and the RFC 8448 vectors are discharged by
   computation. What remains **assumed, not proved** is (a) their
   *cryptographic security* (collision resistance of SHA-256, PRF/HMAC
   security, etc.), and (b) the correctness of AES-GCM / ChaCha20-Poly1305 /
   X25519. The `ml_translatorLib` equality between `tls_sha256` and the CakeML
   `cakeml/sha256.sml` source is Track 2c (structural alignment holds today).
2. **Length-bound side conditions** on the wire round-trips (listed per
   theorem). These are honest consequences of the on-the-wire length fields.

## Spec ↔ implementation gap (HOL spec vs SML vs CakeML)

A **partial** mechanized refinement now links the HOL4 spec to the CakeML port
(Track 2c, `tls_refinementTheory`): the `contentType`, `plaintext`, and
`ciphertext` codecs are **proved equal** to their `cakeml/tls.sml`
counterparts in **both** directions (hand-mirrored, under the byte-representation
map; encode under the honest `< 2^16` bound, decode unconditionally), the
`clientHello`/`serverHello`/`certificate`/`newSessionTicket` **encoders** are
**proved equal** to their CakeML counterparts under their `wf<X>` length
side conditions (with composition corollaries showing the spec decoder inverts
the exact CakeML wire bytes), and the CakeML client dispatcher's control phases
plus the initial ClientHello transition are **proved** to refine the abstract
handshake automaton. The remaining gaps:

* The proved codec refinement is **hand-mirrored, not yet
  `ml_translatorLib`-certified**: the `cml_*` HOL functions are proved equal to
  the spec codecs, but not yet proved to be the deep embeddings the CakeML
  translator extracts from `cakeml/tls.sml` (the certification step of 2c).
* The remaining HOL4 wire codecs' **decode** direction for the four structured
  bodies (`clientHello` / `serverHello` / `certificate` / `newSessionTicket`),
  and the SML `tls.sml`, are still an *independent re-modeling* aligned by
  inspection / covered indirectly via the encode-roundtrip composition — the
  recursive CakeML decoders are **not** yet proved equal as standalone
  equational refinements.
* The key schedule matches the RFC *structurally* and is validated against two
  RFC 8448 byte vectors by computation against a concrete SHA-256; it is not
  yet proved to match the SML/CakeML `TlsKeySchedule` module, and the
  `ml_translatorLib` equality between `tls_sha256` and `cakeml/sha256.sml` is
  still open (structural alignment holds today).
* The handshake theory is an *abstract* state machine. It captures ordering and
  the Finished-before-Connected/AppData safety property, but does not model
  message contents, key installation, or the full server-flight granularity,
  and is not refined to the SML `tlsstate.sml` driver.

In short: the claim supported by these proofs is **"the modeled RFC 8446 wire
round-trips hold (under stated length bounds), the key-schedule construction is
structurally the RFC 8446 §7.1 schedule with correct output lengths, the
abstract handshake automaton never reaches Connected / emits client
application data without a verified peer Finished, and the CakeML
`contentType`/`plaintext`/`ciphertext` codecs (both directions) together with
the `clientHello`/`serverHello`/`certificate`/`newSessionTicket` encoders and
the client dispatcher's control phases provably refine the corresponding HOL
specs (hand-mirrored, modulo the open `ml_translatorLib` certification step and
the structured-decoder direction noted above)."** It is **not** a claim that the
full SML or CakeML code is correct, nor that the underlying cryptography is
secure.
