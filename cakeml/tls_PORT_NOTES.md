# sml-tls → CakeML Port Notes (J3 / L4 — final layer)

## Summary

Ported the TLS-specific SML (`sml-tls`) onto the already-ported CakeML crypto
tower. This is the top layer of the CakeML port; L0–L3
(sha256/bigint/aes/chacha20/x25519/asn1/pem/aead/kdf/rsa/x509) were ported and
verified previously in `cakeml/`.

**Compiler:** CakeML **v3400** (prebuilt bootstrapped `cake-arm8-64`,
`/tmp/cake-arm8-64/cake`, `--target=arm8`). Verified end-to-end: source →
`cake` → `.S` → `cc … basis_ffi.c` → native binary → run.

**Ported source:** `cakeml/tls.sml` — the four core structures
`TlsRecord`, `TlsAlert`, `TlsHandshake`, `TlsKeySchedule` (from upstream
`tls.sml`) plus `TlsRecordProtect` (from `recordprotect.sml`). They are kept in
one file because, as a single CakeML compilation unit, `TlsRecordProtect` must
follow `Aead` and `TlsRecord` in concatenation order.

The handshake state machine (`TlsExtensions`, `TlsCertVerify`, `TlsClient`,
`TlsServer`, from `extensions.sml`/`certverify.sml`/`tlsstate.sml`) is also
ported, in `cakeml/tls_state.sml` — see the "Handshake state machine" section
below.

**Harnesses:** two SELF-CONTAINED single-compilation-unit harnesses that inline
the full dependency-ordered tower + the ported TLS code + a driver, PASSing only
on byte/value match: `cakeml/tls_test.cml` (52/52 core vectors) and
`cakeml/tls_handshake_test.cml` (17/17 in-process handshake).

### Result (real run on the cached `cake`)

```
TLS PORT RESULT: 52 passed, 0 failed
ALL TLS VECTORS PASS
```

Coverage (52 checks, all PASS):

- **Key schedule (RFC 8448 Appendix A)** — byte-exact: `early_secret`,
  `derived(early)`, `handshake_secret`, `derived(handshake)`, `master_secret`,
  and the full `schedule` from the X25519 DHE (`earlySecret`/`handshakeSecret`/
  `masterSecret` components).
- **Record protection (RFC 8448 §3 AES-128-GCM)** — `trafficKey`/`trafficIv`
  reproduce the published server-handshake key/IV; `unprotect` of the real
  674-octet encrypted record yields the exact 657-octet handshake plaintext and
  inner type `Handshake`; `protect` re-encrypts to the exact RFC 8448
  ciphertext; per-record nonce = IV⊕seq (seq 0/1/2); content-type-hiding
  padding strip; tamper → `None` (bad_record_mac); sequence-number advance;
  `maxPlaintext` = 2¹⁴.
- **CertificateVerify (RFC 8446 §4.4.3)** — the signed-content layout (64×0x20,
  context string, single 0x00, transcript hash); a REAL RSA-PSS sign+verify
  using the committed fixtures (`cv-key.pkcs8.der` private key signs, the
  `cv-leaf.der` certificate's extracted RSA public key verifies); fixture
  key↔cert public-key match; tampered-signature rejection; and the
  `TlsKeySchedule.signServerCertVerify`/`verifyServerCertVerify` helpers
  (verifies; rejects wrong transcript; rejects unsupported sigAlg).
- **Message framing round-trips** — TLSPlaintext (single + 2-record stream),
  Alert (incl. `Other`), Handshake message, Extensions, ClientHello,
  ServerHello, Certificate, CertificateVerify, Finished, NewSessionTicket.

No oracle build was needed: the RFC 8448 key-schedule and record vectors are
published byte values (mirrored from `test/test.sml` and `test/record.sml`),
and the CertificateVerify test signs+verifies a real RSA-PSS signature over the
RFC-specified signed content with the committed fixtures, so PASS means the
CakeML port reproduces the published/standard values and a real signature
verifies — not merely that it runs.

## Concatenation / build order

`cakeml/tls_test.cml` is the in-order concatenation (each structure defined
exactly once):

1. `cakeml/kdf.sml` — `Sha256`, `Hmac`, `Kdf` (HKDF-SHA256)
2. `cakeml/bigint.sml` — `BigInt`
3. `cakeml/asn1.sml` — `Asn1`
4. `cakeml/pem.sml` — `Base64`, `Pem`
5. `cakeml/aead.sml` — `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `AesBlock`,
   `AesCtr`, `AesGcm`, `Aead` (this is the self-contained AEAD stack; do NOT
   also include `aes.sml`/`chacha20.sml`, which redefine `AesBlock`/`ChaCha20`)
6. `cakeml/rsa.sml` — `Rsa`
7. `cakeml/x509.sml` — `X509`
8. `cakeml/tls.sml` — `TlsRecord`, `TlsAlert`, `TlsHandshake`,
   `TlsKeySchedule`, `TlsRecordProtect`
9. fixture hex bindings (`cvKeyHex`, `cvLeafHex`) + the test driver

Build:

```sh
cat cakeml/kdf.sml cakeml/bigint.sml cakeml/asn1.sml cakeml/pem.sml \
    cakeml/aead.sml cakeml/rsa.sml cakeml/x509.sml cakeml/tls.sml \
    <fixtures+driver> > tls_test.cml
/tmp/cake-arm8-64/cake --target=arm8 <tls_test.cml >tls_test.S
cc tls_test.S /tmp/cake-arm8-64/basis_ffi.c -lm -o tls_test
./tls_test
```

(`cakeml/tls_test.cml` already contains the full concatenation; it is
self-contained and needs no separate `cat`.)

## Dialect gaps fixed (upstream SML → CakeML)

The crypto-algorithm logic is unchanged; all changes are surface
syntax / basis gaps. The notable ones for the TLS layer:

1. **No records — the dominant change.** Upstream `tls.sml` is record-heavy
   (`tlsPlaintext`, `alert`, `handshakeMessage`, `extension`, `clientHello`,
   `serverHello`, `certificate`/`certificateEntry`, `certificateVerify`,
   `finished`, `newSessionTicket`, `keySchedule`, and `TlsRecordProtect.state`).
   Every record became a **tuple**, every record-argument function a
   tuple-argument function, and every `#field` selector a tuple destructure.
   E.g. `encodePlaintext {contentType, fragment}` → `encodePlaintext (ct, frag)`;
   the 6-field `clientHello`/`serverHello` records → 6-tuples; the key schedule
   record → a 7-tuple returned by `schedule`.
2. **No `Word16`/`Word32`.** All 16/32-bit wire values (versions, cipher
   suites, extension types, signature schemes, named groups, ticket
   lifetime/age) are native `int`; serialization is `div`/`mod`, parsing is
   `*256 + …`. Equality/`<>` on these (suite/scheme comparison) is plain int
   equality.
3. **No `Byte` structure.** `Byte.byteToChar`/`Byte.charToByte` → `Char.chr`/
   `Char.ord` over int bytes (0..255). The few genuine byte XORs (per-record
   nonce, tamper test) use `Word8.xorb (Word8.fromInt a) (Word8.fromInt b)`.
4. **Word literals default to `Word64`.** A `Word8` constant must be written
   `Word8.fromInt 255`, not `0wxFF` (which infers `Word64`).
5. **Curried basis calls.** `String.sub s i`, `String.substring s a b`,
   `String.extract s a None`, `List.tabulate n f`, `Word64.>> w n` — all
   curried in CakeML (upstream uses the tupled SML forms).
6. **No multi-clause `fun … | …`.** Upstream's `contentTypeToByte`/
   `byteToAlertDescription`/`byteToHandshakeType` (clausal) and the
   tuple-recursion helpers (`readCS`/`readComp`) → single clause with
   `case`/`if`; the recursion helpers were also curried.
7. **`Some`/`None`/`True`/`False`** instead of `SOME`/`NONE`/`true`/`false`
   (CakeML capitalises constructors; `True`/`False`/`Ref` per the dialect).
8. **No local `exception` inside `let`** for some decoders → a single
   structure-level `exception Bad` used by `decodeClientHello`/
   `decodeServerHello`, with `(Some (… raise Bad …)) handle Bad => None`. The
   option-threading decoders (`decodeExtensions`, `decodeCertificate`,
   `decodeNewSessionTicket`) were rewritten to thread `option` directly with no
   exception.
9. **No string `\<newline>\` gaps.** The RFC-vector hex literals in the harness
   are single-line strings (the upstream tests use SML line-continuation gaps,
   which `cake` rejects with a parse error).
10. **Char comparison** uses `Char.>=`/`Char.<=` (curried), not polymorphic
    `<`/`>` (used by the harness `fromHex`).
11. **No signatures.** `structure TlsRecord :> TLS_RECORD = struct …` →
    `structure TlsRecord = struct …`; the `.sig` files are dropped.
12. **Ported-tower API shapes.** The TLS layer calls the ported tower, whose
    APIs are tuple/curried (not the upstream records): `Kdf.hkdfExpand
    (prk,info,len)`, `Kdf.hkdfExtract (salt,ikm)`, `Hmac.hmacSha256 key msg`,
    `Sha256.digest`, `Rsa.signPss (priv,SHA256,salt,msg)` / `Rsa.verifyPss
    (pub,SHA256,saltLen,msg,sgn)`, `Rsa.decodePkcs8Der`, `Rsa.pubOf`,
    `X509.parse`, `X509.rsaPublicKey c : Rsa.pubkey option`, and the AEAD
    constructors `Aead.AAesGcm128`/`AAesGcm256` with `Aead.seal alg
    (key,nonce,aad,pt)` / `Aead.open' alg (…)` returning `string option`.

## Scope / notes

- The port is of the **pure protocol logic** (sans-IO): byte-string codecs,
  the key schedule, record protection, and signature verification. No real
  sockets are needed or used — the caller owns the transport, exactly as in
  upstream.
- `TlsKeySchedule.signServerCertVerify` uses a fixed all-zero 32-byte PSS salt
  (as upstream) so signatures are reproducible.
- PSK-resumption helpers (`resumptionMasterSecret`, `resumptionPsk`,
  `binderKey`, `binderFinishedKey`, `pskBinder`) are ported for completeness.

## Handshake state machine (the capstone — also ported & verified)

On top of the core, the handshake state machine was ported and verified with a
real in-process client↔server 1-RTT handshake:

**Ported source** — `cakeml/tls_state.sml`:

| Upstream | Ported structure | Notes |
|---|---|---|
| `extensions.sml` | `TlsExtensions` | All extension codecs (key_share CH/SH/HRR, supported_versions, supported_groups, signature_algorithms, SNI, ALPN, cookie, psk_key_exchange_modes, early_data, pre_shared_key) + `negotiateVersion/Group/SigAlg` + downgrade sentinels. Word16/32/8 → `int`; records → tuples. |
| `certverify.sml` | `TlsCertVerify` | Full RFC 5280 path validation (chain build, validity window, BasicConstraints CA + pathLen, KeyUsage `keyCertSign`, EKU `serverAuth`, sig-alg enforcement, X509 signature verification, RFC 6125 wildcard hostnames). X509 record patterns (`{notBefore,notAfter}`, `{pathLen,…}`, `RsaPss {hash,…}`) → the ported tower's tuple/accessor + curried-constructor forms. ECDSA/Ed25519 unsupported (matches upstream). |
| `tlsstate.sml` | `TlsClient`, `TlsServer` | ~22-field records → positional tuples (15-tuple client / 12-tuple server). Covers `startHandshake`, `processServerHello`, server-flight decrypt/`processFlight`, client `step` (incl. the J2 coalesced ServerHello+CCS+flight in one step), and server `receiveClientHello`/`produceServerHello`/`produceServerFlight`/`step`, plus the real CV sign+verify. |

**Harness** — `cakeml/tls_handshake_test.cml` (self-contained: tower +
`x25519.sml` + `tls.sml` + `tls_state.sml` + driver). Compiled with `cake`
v3400, linked, ran:

```
HANDSHAKE RESULT: 17 passed, 0 failed
ALL HANDSHAKE CHECKS PASS
```

The PASSes are real: client and server opaque states are driven directly
in-process (handshake records passed as byte strings between them, no sockets),
reaching **CONNECTED**; "agree on app key" is tuple equality of independently
derived `(key,iv)` pairs on each side; the coalesced ServerHello+CCS+flight is
processed in a single `step`; and "CertificateVerify verified" is a genuine
`Rsa.verifyPss` over the transcript hash against the fixture leaf's public key.

### Handshake concatenation order

`cakeml/kdf.sml` + `bigint.sml` + `asn1.sml` + `pem.sml` + `aead.sml` +
`rsa.sml` + `x509.sml` + **`x25519.sml`** (inserted here for the ECDHE key
exchange; `pow2` is structure-local so it introduces no top-level clash) +
`tls.sml` + `tls_state.sml` + driver.

### Handshake-layer dialect notes / scope limits

- **P256 is not ported.** Upstream `tlsstate` references P256 only for the
  optional P-256 key-exchange path; the tests use X25519 with
  `p256PrivateKey = None`, so every P256 branch is stubbed (unsupported/raise).
- **The `Tls` re-export bundle is not expressible.** CakeML's grammar forbids
  nested `structure` declarations and structure abbreviations, so the upstream
  `structure Tls` that re-exports the others has no equivalent — the six
  structures are simply top-level instead. (Confirmed with a 3-line probe.)
- **Out of scope** for the handshake harness (focused on the 1-RTT path):
  HelloRetryRequest, KeyUpdate, `sendApplicationData`, NewSessionTicket
  issuance, and post-handshake `stepConnected`. The encode/decode codecs for
  these messages are present in the ported `TlsHandshake` (and round-trip
  in `tls_test.cml`); only the state-machine driving of them is omitted.

## Files

- `cakeml/tls.sml` — ported TLS core (TlsRecord/TlsAlert/TlsHandshake/
  TlsKeySchedule + TlsRecordProtect)
- `cakeml/tls_state.sml` — ported handshake state machine (TlsExtensions/
  TlsCertVerify/TlsClient/TlsServer)
- `cakeml/tls_test.cml` — self-contained core-vector harness (tower + TLS +
  driver), **52/52 PASS** on `cake` v3400
- `cakeml/tls_handshake_test.cml` — self-contained in-process client↔server
  handshake harness (tower + x25519 + TLS + tls_state + driver),
  **17/17 PASS** on `cake` v3400
- `cakeml/tls_PORT_NOTES.md` — this file
