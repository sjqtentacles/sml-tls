# sml-tls

[![CI](https://github.com/sjqtentacles/sml-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-tls/actions/workflows/ci.yml)

TLS 1.3 (RFC 8446) record layer, handshake messages, HKDF key schedule, and
client/server state machines for Standard ML -- a pure, **sans-IO** state
machine. The caller owns the transport: feed bytes received from the peer to
`TlsClient.step` / `TlsServer.step`, receive back the bytes to send, and put
them on the wire yourself. No sockets, no threads, no global state.

> [!WARNING]
> **Experimental — not for production security.** This is a reference /
> educational implementation. It is verified against the RFC 8448 test vectors,
> but passing key-schedule vectors is not the same as being safe to terminate
> real TLS traffic. Pure SML arithmetic is **not constant-time** (timing
> side-channel exposure), the handshake and certificate-chain validation paths
> are only partially exercised, and it has had no security audit. Do not use it
> to protect real secrets or in any setting where an adversary is present.

Part of the `sjqtentacles` monorepo of SML libraries. It builds on the
vendored crypto family:
[`sml-kdf`](https://github.com/sjqtentacles/sml-kdf) (HKDF),
[`sml-aead`](https://github.com/sjqtentacles/sml-aead) (AES-GCM / ChaCha20-Poly1305),
[`sml-x25519`](https://github.com/sjqtentacles/sml-x25519) (Curve25519 DH),
[`sml-codec`](https://github.com/sjqtentacles/sml-codec) (SHA-256),
[`sml-rsa`](https://github.com/sjqtentacles/sml-rsa) (RSA-PSS), and
[`sml-x509`](https://github.com/sjqtentacles/sml-x509) (certificate parsing).

## Features

- **Record layer** (`TlsRecord`): `TLSPlaintext` / `TLSCiphertext` encode and
  decode with streaming support (decode returns trailing bytes so a caller can
  parse a record stream).
- **Alert protocol** (`TlsAlert`): all RFC 8446 alert levels and descriptions,
  with an `Other` case that round-trips unmapped codes.
- **Handshake messages** (`TlsHandshake`): ClientHello, ServerHello,
  EncryptedExtensions, Certificate, CertificateVerify, Finished, and
  NewSessionTicket -- encode and decode against the RFC 8446 wire format.
  Extension framing (2-byte type / 2-byte length) is exposed as a reusable
  helper.
- **Key schedule** (`TlsKeySchedule`): the HKDF-based 1-RTT key schedule from
  RFC 8446 §7.1 -- `earlySecret`, `handshakeSecret`, `masterSecret`,
  `hkdfExpandLabel`, `deriveSecret`, traffic-key/IV expansion, and the
  Finished `verify_data` computation. Verified byte-for-byte against the
  RFC 8448 test vectors.
- **Client / server state machines** (`TlsClient` / `TlsServer`): pure
  `step : state * bytes -> state * bytes list` transitions. The opaque state
  carries the negotiated cipher suite, traffic keys, and transcript.

## Status

The record layer, alert codec, handshake message codecs, and the full
key schedule are complete and tested against RFC 8448 vectors. The client
and server state machines implement the 1-RTT handshake skeleton
(ClientHello/ServerHello production, key-share extraction, traffic-key
derivation). Record-layer AEAD encryption/decryption is delegated to the
caller, who uses the traffic keys extracted from the state together with
the vendored `sml-aead` -- this keeps the core sans-IO.

## Portability

Pure Standard ML using only the Basis library plus the vendored crypto
family -- no FFI, no threads. Verified on **MLton** and **Poly/ML**, with
identical, deterministic output across both.

## Building and testing

```sh
make test        # build + run the suite under MLton (default)
make test-poly   # run the suite under Poly/ML
make all-tests   # run under both
make clean
```

## Usage

```sml
(* Client: start a 1-RTT handshake. *)
val clientPriv = (* 32-byte X25519 private key, from your RNG *)
val cfg = {
  x25519PrivateKey = clientPriv,
  clientRandom = (* 32 bytes from your RNG *),
  legacySessionId = "",
  cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
  extensions = []
} : TlsClient.clientConfig

val (cst, clientHelloRecord) = TlsClient.startHandshake cfg
(* Send clientHelloRecord on the wire. When the ServerHello arrives,
   feed it (decrypted) to step: *)
val (cst', toSend) = TlsClient.step (cst, serverHelloBytes)

(* The state exposes the negotiated traffic keys, which the caller uses
   with sml-aead to protect/decrypt records: *)
val SOME (sHsKey, sHsIv) = TlsClient.serverHandshakeKey cst'
```

```sml
(* Key schedule: verify against RFC 8448. *)
val earlySecret = TlsKeySchedule.earlySecret
  {psk = TlsKeySchedule.zeros}  (* no PSK *)
val handshakeSecret = TlsKeySchedule.handshakeSecret
  {earlySecret = earlySecret, dhe = sharedX25519Secret}
val masterSecret = TlsKeySchedule.masterSecret
  {handshakeSecret = handshakeSecret}
```

## API summary

| Structure | Function | Description |
| --- | --- | --- |
| `TlsRecord` | `encodePlaintext` / `decodePlaintext` | Wire codec for `TLSPlaintext`. |
| `TlsRecord` | `encodeCiphertext` / `decodeCiphertext` | Wire codec for `TLSCiphertext`. |
| `TlsAlert` | `encode` / `decode` | 2-byte alert body codec. |
| `TlsHandshake` | `encodeMessage` / `decodeMessage` | Handshake message framing (type + 3-byte length). |
| `TlsHandshake` | `encodeClientHello` / `decodeClientHello` | ClientHello body codec. |
| `TlsHandshake` | `encodeServerHello` / `decodeServerHello` | ServerHello body codec. |
| `TlsHandshake` | `encodeCertificate` / `decodeCertificate` | Certificate list codec. |
| `TlsHandshake` | `encodeCertificateVerify` / `decodeCertificateVerify` | CertificateVerify codec. |
| `TlsHandshake` | `encodeFinished` / `decodeFinished` | Finished verify_data codec. |
| `TlsHandshake` | `encodeNewSessionTicket` / `decodeNewSessionTicket` | NewSessionTicket codec. |
| `TlsKeySchedule` | `earlySecret` / `handshakeSecret` / `masterSecret` | The three HKDF-Extract stages. |
| `TlsKeySchedule` | `hkdfExpandLabel` | RFC 8446 HKDF-Expand-Label. |
| `TlsKeySchedule` | `deriveSecret` | RFC 8446 Derive-Secret. |
| `TlsKeySchedule` | `trafficKey` / `trafficIv` | Traffic key/IV expansion. |
| `TlsKeySchedule` | `finishedKey` / `finishedVerifyData` | Finished verify_data computation. |
| `TlsKeySchedule` | `schedule` | Full 1-RTT key schedule. |
| `TlsClient` | `startHandshake` | Produce a ClientHello record. |
| `TlsClient` | `step` | Feed received bytes; get updated state + bytes to send. |
| `TlsServer` | `receiveClientHello` / `produceServerHello` | Server-side handshake initiation. |

## Sans-IO design

This library implements the TLS 1.3 protocol *logic* with no network I/O.
The caller is responsible for:

1. Generating randomness (client/server random, X25519 private keys).
2. Putting outgoing records on the wire.
3. Performing record-layer AEAD encryption/decryption using the traffic
   keys extracted from the state and the vendored `sml-aead` library.

This makes the handshake fully deterministic and testable against fixed
RFC 8448 vectors: identical inputs produce byte-identical outputs on both
MLton and Poly/ML.

## Installing with smlpkg

```sh
smlpkg add github.com/sjqtentacles/sml-tls
smlpkg sync
```

Then reference the library basis from your own `.mlb`:

```
lib/github.com/sjqtentacles/sml-tls/sml-tls.mlb
```

For Poly/ML, `use` the sources listed in `sources.mlb` in order (the
vendored crypto family first, then `tls.sig` and `tls.sml`).

## License

MIT. See [LICENSE](LICENSE).
