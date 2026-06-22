# Integration contract (J1 integrator's checklist)

This document is the **J1 join-point checklist**: exactly where each
parallel track's deliverable plugs into the `TlsClient.step` /
`TlsServer.step` state machine in
[`lib/github.com/sjqtentacles/sml-tls/tls.sml`](lib/github.com/sjqtentacles/sml-tls/tls.sml),
and which state fields each adds. It was frozen in Phase 0 so the
integrator does not re-discover the seams.

The Phase 0 stubs (`TlsRecordProtect`, `TlsCertVerify`, `TlsExtensions`)
are wired into the build ([`sources.mlb`](lib/github.com/sjqtentacles/sml-tls/sources.mlb))
and the test suite ([`test/sources.mlb`](test/sources.mlb),
[`test/entry.sml`](test/entry.sml)) but their bodies currently `raise
Fail "todo: A1|A2|A3"`. The J1 integrator replaces the seams below with
real calls once each track's TDD work is green.

## Current state machine (pre-J1)

`TlsClient` / `TlsServer` carry:

- `x25519PrivateKey`, `clientRandom` / `serverRandom`, `legacySessionId`,
  `cipherSuites` / `cipherSuite`, `extensions` (a `TlsHandshake.extension list`).
- The negotiated `keySchedule` (all seven secrets from `TlsKeySchedule.schedule`)
  after the ServerHello is processed.
- Traffic-key accessors (`serverHandshakeKey`, `clientHandshakeKey`,
  `serverAppKey`, `clientAppKey`) that return `(key, iv)` options.
- A `transcript` accumulator (concatenated wire-form handshake messages).

**Gap the J1 integrator closes:** record AEAD is currently *offloaded to
the caller* (see `tls.sig` lines 422-440 — "the caller does that using
traffic keys extracted from the state"). There is no HelloRetryRequest,
no extension negotiation/enforcement, no certificate-chain validation,
no KeyUpdate / NewSessionTicket / resumption, and only limited alert-on-error.

## A1 — Record-layer protection (`TlsRecordProtect`) → into `step`

**Seam:** every place `TlsClient.step` / `TlsServer.step` currently hands
the caller a plaintext record to AEAD-protect/decrypt, the state machine
instead calls `TlsRecordProtect`.

**New state fields** (added to `clientState` / `serverState`):

- `serverWriteProtect : TlsRecordProtect.state option`
  — initialised with `TlsRecordProtect.init {key, iv}` from the server
  handshake-traffic key once the ServerHello is processed; re-initialised
  from the server application-traffic key after the server Finished.
- `clientWriteProtect : TlsRecordProtect.state option`
  — same, for the client's write direction (handshake then application).
- `serverReadProtect  : TlsRecordProtect.state option`
  — the peer's write direction seen from our side (the inverse).
- `clientReadProtect  : TlsRecordProtect.state option`

**Call sites in `step`:**

- **Outbound:** before emitting any post-ServerHello record, the state
  machine calls
  `TlsRecordProtect.protect {state, innerType, plaintext, pad}`
  to produce the `TLSCiphertext` body, then `TlsRecord.encodeCiphertext`
  for the 5-byte header. `innerType` is `Handshake` during the handshake,
  `ApplicationData` afterwards, `Alert` for alerts.
- **Inbound:** `TlsRecord.decodeCiphertext` parses the 5-byte header, then
  `TlsRecordProtect.unprotect {state, record}` authenticates and strips
  padding. `NONE` → emit `bad_record_mac` (fatal); plaintext longer than
  `TlsRecordProtect.maxPlaintext` → `record_overflow` (fatal).

**Replaces:** the `trafficKeys` accessor pattern and the "caller does
record decryption" note in `tls.sig` (the accessor stays for
inspection/testing, but `step` no longer requires the caller to AEAD).

## A3 — Extension negotiation (`TlsExtensions`) → into `step` + CH/SH build

**Seam:** `TlsClient.startHandshake` / `TlsServer.produceServerHello`
build the ClientHello/ServerHello extension lists; `step` parses the
peer's extensions and enforces negotiation.

**New state fields:**

- `negotiatedGroup : Word16.word option` — the selected key-share group
  (X25519 today, P-256 after A4).
- `negotiatedSigAlg : Word16.word option` — the selected signature
  algorithm for CertificateVerify.
- `downgradeChecked : bool` — set once the ServerHello.random is
  confirmed free of the `downgradeSentinelTls12` / `downgradeSentinelTls11`
  sentinels (§4.1.3).

**Call sites:**

- **CH build:** `TlsExtensions.encodeSupportedVersionsCH`,
  `encodeSupportedGroups`, `encodeKeyShareCH`, `encodeSignatureAlgorithms`,
  `encodeServerName`, `encodeAlpn` produce the ClientHello extension
  bodies (currently the state machine builds these inline).
- **SH parse:** `TlsExtensions.decodeSelectedVersionSH`,
  `decodeKeyShareSH` parse the ServerHello extensions; `negotiateGroup`
  / `negotiateSigAlg` / `negotiateVersion` pick the agreed parameters.
- **Enforcement:** if negotiation yields `NONE` → `handshake_failure` /
  `illegal_parameter` as appropriate; if a downgrade sentinel is present
  in `ServerHello.random` → `illegal_parameter`.
- **HelloRetryRequest (new):** if the server rejects the client's
  `key_share` / `supported_groups`, it emits an HRR with a `cookie`
  extension; the client's `step` must handle the synthetic
  `MessageHash` transcript reset (§4.1.3) using
  `TlsKeySchedule` + the HRR message.

## A2 — Certificate-chain validation (`TlsCertVerify`) → at the Certificate step

**Seam:** when `step` receives the server's `Certificate` message (client
side) or the client's `Certificate` (server side, if requested).

**New state fields:**

- `trustStore : string list` — caller-supplied DER trust anchors (passed
  in via `clientConfig` / `serverConfig`).
- `now : int` — injected unix time (caller-supplied, keeps the library pure).
- `sigAlgs : Word16.word list` — acceptable signature algorithms.

**Call site in `step` (client side):** after parsing the server
`Certificate` and `CertificateVerify`:

1. `TlsCertVerify.verifyChain {chain, trust, hostname, now, sigAlgs}`
   → `Valid` continues the handshake; `Invalid desc` → emit `desc`
   (fatal) and abort.
2. The `CertificateVerify` signature itself is verified separately
   (RSA-PSS via `Rsa`, ECDSA via A4 `P256` once wired). A failed
   signature → `decrypt_error`.

**Hostname:** comes from the caller (a new `clientConfig` field); matched
via `TlsCertVerify.matchHostname` against the leaf's SAN/CN.

## A4 — `sml-p256` (NIST P-256) → `key_share` + `signature_algorithms`

**Seam:** once `sml-p256` is vendored into `lib/github.com/sjqtentacles/`,
it adds a second key-share group and ECDSA signature scheme.

**New constants** (in `TlsHandshake`):

- `groupSecp256r1 : Word16.word` = `0x0017` (§4.2.7) — alongside
  `groupX25519` (`0x001d`).
- `sigEcdsaSecp256r1Sha256 : Word16.word` = `0x0403` (already present).

**New state fields:**

- `p256PrivateKey : string option` — caller-supplied 32-byte scalar
  (alongside `x25519PrivateKey`).

**Call sites:**

- `key_share`: the client may now offer both X25519 and P-256 entries;
  the server's `negotiateGroup` picks one. ECDH uses
  `P256.ecdh {privateKey, peerPublic}`.
- `CertificateVerify`: ECDSA signatures (`sigEcdsaSecp256r1Sha256`)
  verified via `P256.ecdsaVerify {publicKey, message, signatureDer}`.

## Alert state machine (J1)

J1 also wires the full alert mapping: every protocol violation in `step`
that currently raises `Tls` instead emits the correct fatal `TlsAlert`
(record-wrapped under the current traffic key via `TlsRecordProtect`)
and transitions to a terminal `Error` state. This is the single biggest
behavioural change for the integrator.

## Out of scope for J1

- A5 conformance/fuzz harnesses (those run at J2 against the J1 result).
- B1 HOL4 spec and B2 CakeML port (parallel; feed J3/J4, not J1).
- Revocation via CRL (OCSP stapling parsing is in A2; CRL deferred).
