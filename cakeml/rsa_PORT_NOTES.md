# sml-rsa → CakeML Port Notes

## Summary

Ported `sml-rsa` (RFC 8017 / PKCS#1 v2.2) to the CakeML subset. Compiles with
the pinned `cake` v3400 compiler and reproduces, **byte-for-byte**, the
vectors emitted by the *original* `sml-rsa` built under MLton (the oracle):

- RSASSA-PKCS1-v1_5 sign + verify (SHA-256)
- RSASSA-PSS sign + verify (SHA-256, explicit 32-byte salt)
- RSAPublicKey / RSAPrivateKey (PKCS#1), SubjectPublicKeyInfo (SPKI) and
  PKCS#8 PrivateKeyInfo DER encode (byte-match) and decode (value-match)
- EME-PKCS1-v1_5 and EME-OAEP encrypt/decrypt round-trips

18/18 checks PASS → `ALL PASS`. The key, signatures and DER blobs are a
fixed deterministic 2048-bit key generated once by the MLton oracle and
hard-coded into the harness.

## Scope vs. the original

- **Key generation (`generate`) is omitted.** It needs Miller-Rabin primality
  testing (`BigInt.isProbablePrime`), which is not part of the CakeML bigint
  port. Not required by the deliverable; the test key comes from the oracle.
- **Only SHA-256** is wired into `hashBytes` (the one hash the test vectors and
  the X.509 chain use). `SHA1`/`SHA512` remain in the `hash` datatype with
  their correct OIDs/lengths, but `hashBytes` raises for them — the L0 tower
  has no SHA-1/SHA-512 CakeML port yet.
- Everything else (RSAEP/RSADP via CRT, EMSA-PKCS1-v1_5, EMSA-PSS, EME-OAEP,
  EME-PKCS1-v1_5, MGF1, I2OSP/OS2IP, modInverse, all DER/PEM codecs) is ported
  faithfully.

## Dialect-gap fixes applied

1. **No records.** `{ n = 5, e = 3 }` is a *parse error* in cake. The record
   types `pubkey`/`privkey` became curried-constructor datatypes
   `Pub int int` / `Priv int int int int int int int int`, and every
   record-argument function (`sign {priv,hash,msg}`, `verify {...}`, …) became
   a tuple-argument function (`sign (priv,hash,msg)`, …). All `#field`
   selectors were removed (destructure via the constructor pattern).
2. **BigInt → native `int`.** CakeML's `int` is already arbitrary precision
   (same choice the asn1 port made), so `B.modpow`/`B.divMod`/`B.quotRem`/
   `B.add`/`B.mul`/… became native `mod`/`div`/`+`/`*`. `modpow` is a local
   square-and-multiply; `modInverse` is the extended-Euclid loop on native
   `int`. This also lets the codec hand `Asn1.Int n` a native `int` directly.
   A 2048-bit modpow runs in ~0.13 s, so no perf shim was needed.
3. **No polymorphic comparison operators.** `c >= #"0"` is a type error
   (`>=` is `int -> int -> bool`); char comparisons use `Char.>=`/`Char.<=`.
   Integer/string/`int list` equality via `=` works fine (used for OID match).
4. **No signature ascription.** `structure Rsa :> RSA = struct` →
   `structure Rsa = struct`.
5. **Multi-clause `fun ... | ...` → single clause + `case`.** `fromHex`'s
   `loop` and `nonZeroPad`'s `take` were rewritten with `case`.
6. **`SOME`/`NONE`/`true`/`false` → `Some`/`None`/`True`/`False`**; single-arg
   `fn`.
7. **Tupled basis calls made curried.** `String.sub s i`,
   `String.substring s a b`, `String.extract s a None`, `List.tabulate n f`.
8. **Byte XOR via `Word64`.** CakeML `int` has no bitwise xor, so `xorStr`
   xors bytes through `Word64.xorb`. The PSS top-bit mask (`0xFF >> nbits`)
   likewise uses `Word64.>>`. (The original used `Word.*`/`IntInf.*`.)
9. **`Char.isSpace`** is in the basis, but a tiny local `isSpace` is used to
   keep `fromHex` self-contained / explicit.
10. **Records in the *test* removed too** — the harness uses the tuple-arg API.

## Cross-check methodology (the oracle)

`/tmp/cake-oracle` builds the unmodified `lib/.../sml-rsa/rsa.{sig,sml}` (plus
its real deps: sml-bigint, sml-codec, sml-asn1, sml-pem) with **MLton**, then
generates a deterministic 2048-bit key and prints the PKCS#1 v1.5 / PSS
signatures and the four DER encodings as hex. The CakeML harness hard-codes
those and asserts exact equality. So "PASS" means the CakeML port agrees with
the production SML library bit-for-bit, not merely "runs without error".

## Files

- `cakeml/rsa.sml` — ported library source
- `cakeml/rsa_test.cml` — inlined Sha256+Asn1+Pem+Rsa + cross-check driver
- `cakeml/rsa_PORT_NOTES.md` — this file
