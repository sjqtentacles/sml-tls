# sml-asn1 → CakeML Port Notes

## Summary

Ported `sml-asn1` (X.690 DER encoder/decoder, common subset) to the CakeML
subset. `encode` and `decode` compile with the pinned `cake` v3400 compiler
and reproduce standard DER vectors byte-for-byte: minimal two's-complement
INTEGER edge cases, RFC 5280 / PKCS OIDs, BOOLEAN/NULL/OCTET STRING/UTF8,
SEQUENCE/SET/context-tag, plus encode→decode→encode round-trips.

## Dialect-gap fixes applied

1. **`datatype der = ... of ...` → curried Haskell-style constructors.**
   `Int of B.int` → `Int int`, `Oid of int list` → `Oid (int list)`,
   `Context of int * der` → `Context int der`. Constructor application
   `Context (n, d)` → `Context n d`.
2. **BigInt dependency eliminated.** The original carries INTEGER values in
   the vendored `BigInt`. CakeML's `int` is already arbitrary precision, so
   `B.int` → `int`, `B.add/sub/mul` → `+`/`-`/`*`, `B.~` → `~`,
   `B.compare (n, zero) = EQUAL` → plain `n = 0`/`n > 0`/`n < 0`,
   `B.divMod (n, b256)` → `(n div 256, n mod 256)`, `B.pow (two, k)` → a
   local `pow2`. This removed the need to inline the bigint port at L1.
3. **Tupled basis calls made curried.** `String.sub (s, i)` → `String.sub s i`,
   `String.substring (s, a, b)` → `String.substring s a b`,
   `String.extract (s, 1, NONE)` → `String.extract s 1 None`,
   `List.tabulate (n, f)` → `List.tabulate n f`. (User-defined tuple-arg
   helpers like `byteAt (s, i)` were kept tupled — only the *basis* calls
   needed currying.)
4. **Multi-clause `fun ... | ...` → single clause with `case`.** The OID
   `mark` helper (`mark (_, []) = ... | mark (i, x::xs) = ...`) became one
   clause matching on the list with `case`.
5. **`SOME`/`NONE`/`valOf` → `Some`/`None`/`Option.valOf`.** (Only `decodeOpt`
   used options; `valOf (B.toInt r)` disappeared with the BigInt removal.)
6. **`true`/`false` → `True`/`False`** in the `readSub` recursion flags.
7. **Integer `case` patterns rewritten as `if`/`else`.** `case cls of 0 => …
   | 2 => … | _ => …` and `case byteAt (...) of 0x00 => … | 0xFF => …` use
   literal-int patterns, which are avoided here for portability; rewritten as
   `if cls = 0 then … else if cls = 2 then … else …`.
8. **No signature ascription.** `structure Asn1 :> ASN1 = struct` →
   `structure Asn1 = struct`.

## Things that worked unchanged

- Mutually recursive `fun parseTLV … and parseMany …`.
- `case … of (a0 :: a1 :: rest) => …`, nested `let`/`val`.
- `andalso`/`orelse`, `not`, `@`, exception raising with string payload.
- `handle _ => None` in `decodeOpt`.

## Test vectors (all PASS)

INTEGER: 0, 127, 128, 256, -1, -128, -129, 65537 (minimal two's-complement);
BOOLEAN true/false; NULL; OIDs 2.5.4.3 (commonName), 1.2.840.113549.1.1.11
(sha256WithRSAEncryption), 1.2.840.113549.1.1.1 (rsaEncryption);
OCTET STRING; UTF8String; SEQUENCE; explicit context [0]; a decode→encode
round-trip of an external DER blob; a nested SEQUENCE/SET/context round-trip;
and a decoded INTEGER value check (-129). 21/21 PASS, `ALL PASS`.

## Files

- `cakeml/asn1.sml` — ported library source
- `cakeml/asn1_test.cml` — inlined source + DER vector driver
- `cakeml/asn1_PORT_NOTES.md` — this file
