# sml-x509 → CakeML Port Notes

## Summary

Ported `sml-x509` (RFC 5280 certificate parsing + RSA signature verification)
to the CakeML subset. Compiles with the pinned `cake` v3400 compiler and
reproduces the field extractions and signature-verification verdicts of the
*original* `sml-x509` built under MLton (the oracle), on the committed test
fixtures `test/fixtures/certs/{leaf,intermediate,root}.der` (a real
leaf → intermediate → root chain, RSASSA-PKCS1-v1_5 with SHA-256).

17/17 checks PASS → `ALL PASS`, including:

- leaf subject CN (`www.example.com`), full DN, issuer DN, notBefore/notAfter,
  serial (hex), and the RSA public key `n`/`e` (exact decimal match)
- `verifySignature (leaf, intermediate)` = `Verified` (real RSA verify over the
  verbatim tbsCertificate bytes), and it rejects the wrong issuer (root)
- `intermediate.isCA`, `verifySignature (intermediate, root)` = `Verified`
- `verifySelfSigned root` = `Verified`
- `verifyChain (leaf, [intermediate], [root], time)` = `ChainOk`
- a one-byte-flipped leaf signature is rejected

## Dialect-gap fixes applied

1. **No records — the biggest change.** `{ … }` is a *parse error* in cake.
   Every record became a datatype or tuple, and every `#field` selector a
   constructor accessor / tuple destructure:
   - the 15-field `cert` record → `datatype cert = Cert …15 curried fields…`
     with one accessor function each (`subject`, `validity`, `signatureValue`,
     `tbsCertificateDer`, …);
   - the 7-field DER `node` record → `datatype node = Node int bool int int int
     int int` with accessors `nCls/nCon/nTag/nStart/nCOff/nCLen/nEnd`;
   - `time` → `datatype time = Time int int int int int int`;
   - `attribute {oid,value}` → `(int list * string)`;
     `extension {oid,critical,value}` → `(int list * bool * string)`;
     `validity {notBefore,notAfter}` → `(time * time)`;
     `basicConstraints {ca,pathLen}` → `(bool * int option)`;
   - `RsaPss of {hash,saltLen}` → `RsaPss Rsa.hash int`.
   - record-argument functions `verifySignature {cert,issuer}` and
     `verifyChain {cert,intermediates,roots,time}` → tuple-argument functions.
2. **`o` is reserved** (the composition operator) and cannot be bound as a
   variable: the `node` content-offset accessor used `o` → renamed to `co`.
   (This was the one non-mechanical surprise; it surfaces as a bare
   "parse error" pointing at the enclosing `structure`.)
3. **BigInt → native `int`** for the serial number (`bigUnsigned`) and the RSA
   key, consistent with the rsa/asn1 ports.
4. **No polymorphic comparison operators / `order`.** `Int.compare` (curried,
   returns `Less`/`Equal`/`Greater`) drives `compareTime`; the `chain`
   continuation helper matches on the capitalized `order` constructors.
   Equality `=`/`<>` on strings, `int list` (OIDs) and the nullary
   `verifyResult`/`order` constructors works.
5. **Multi-clause `fun ... | ...` → single clause + `case`** (`keyUsage`'s
   `pick`, `parsePssParams`'s `scan`, the `chain`/continuation in
   `compareTime`).
6. **`Word.* ` bit ops → `Word64.*`** in the keyUsage bit test
   (`Word64.<< (0w1 : Word64.word) (7 - (i mod 8))`).
7. **`SOME`/`NONE`/`true`/`false` → `Some`/`None`/`True`/`False`**; single-arg
   `fn`; tupled basis calls curried (`String.substring s a b`,
   `String.extract s a None`, `String.sub s i`); `(… handle _ => None)` /
   `(… handle _ => [])` wrappers parenthesized.
8. **No signature ascription.** `structure X509 :> X509 = struct` →
   `structure X509 = struct`.

## Scope

The whole public surface is ported: `parse`/`parsePem`, all field accessors
(`version`, `serialNumber`, `serialHex`, `signatureAlg`, `issuer`, `subject`,
`validity`, `notBefore`, `notAfter`, `publicKeyAlg`, `tbsCertificateDer`,
`subjectPublicKeyInfoDer`, `signatureValue`, `rsaPublicKey`), the name helpers
(`commonName`, `nameToString`), time (`compareTime`, `timeToString`), the
extension accessors (`extensions`, `findExtension`, `basicConstraints`, `isCA`,
`keyUsage`, `extKeyUsage`, `dnsNames`, `subjectKeyId`, `authorityKeyId`), and
verification (`verifySignature`, `verifySelfSigned`, `verifyChain`).
Verification is RSA-only (PKCS#1 v1.5 + PSS), exactly as in the original; EC /
Ed25519 still parse and report `Unsupported`. SHA-256 is the only hash wired
through `Rsa.hashBytes`, which is what the fixtures (and essentially all real
RSA certs) use.

## Cross-check methodology (the oracle)

`/tmp/cake-oracle` builds the unmodified `lib/.../sml-x509/x509.{sig,sml}`
(plus sml-rsa/bigint/codec/asn1/pem) with **MLton**, parses the same three
fixture certs, and prints the extracted fields and verification verdicts. The
CakeML harness embeds the certs (as hex) and asserts byte/value-exact equality
with that output. "PASS" therefore means the CakeML port agrees with the
production SML library, not merely that it runs.

## Files

- `cakeml/x509.sml` — ported library source
- `cakeml/x509_test.cml` — inlined Sha256+Asn1+Pem+Rsa+X509 + cross-check driver
- `cakeml/x509_PORT_NOTES.md` — this file
