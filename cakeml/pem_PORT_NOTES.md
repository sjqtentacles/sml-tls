# sml-pem → CakeML Port Notes

## Summary

Ported `sml-pem` (RFC 7468 PEM) plus the `Base64` codec it depends on (from
the vendored `sml-codec`, RFC 4648) to the CakeML subset. Both compile with
the pinned `cake` v3400 and reproduce the RFC 4648 §10 Base64 vectors, PEM
encode/decode round-trips, CRLF handling, and 64-column body chunking,
byte-for-byte.

Because the CakeML tower has no standalone base64 port, `Base64` is inlined
into `pem.sml` ahead of `Pem`.

## Dialect-gap fixes applied

1. **Records → tuples.** CakeML has no records. The API
   `encode {label, der}` / `decode : string -> {label, der} list` became
   `encode (label, der)` / `decode : string -> (string * string) list`.
   `finishBlock` returns `(label, der)` instead of `{label = …, der = …}`.
2. **Multi-clause `fun ... | ...` → single clause + `case`.** The mutually
   recursive `collect`/`scan` (and their `[]` / `l :: rest` clauses) were
   rewritten to take the list argument and `case` on it. `fun … and …` mutual
   recursion is kept.
3. **Tupled basis calls made curried.** `Vector.sub (a, i)` → `Vector.sub a i`,
   `String.substring (s, a, b)` → `String.substring s a b`,
   `String.sub (l, i)` → `String.sub l i`, `String.fields f s` stays curried.
4. **`SOME`/`NONE` → `Some`/`None`; `true`/`false` → `True`/`False`** (the
   `pad` flag in `Base64.encode`/`encodeUrl`).
5. **Char comparisons curried.** `c >= #"A"` → `Char.>= c #"A"`,
   `c = #"="` → `Char.= c #"="`, `c <> #"="` → `not (Char.= c #"=")`.
6. **No signature ascription** (`:> PEM`, `:> BASE64` dropped).

## Notable non-issues

- `String.isPrefix` / `String.isSuffix` / `String.fields` exist in the CakeML
  basis (curried) and behave as expected — PEM boundary parsing needed no
  reimplementation.
- The `go`/`collect`/`deval` helpers in Base64 already used `case`, so only
  the constructor/tuple-call surface changed.

## Test vectors (all PASS)

- RFC 4648 §10 Base64 encode: `""`,`f`,`fo`,`foo`,`foob`,`fooba`,`foobar`
  → `""`,`Zg==`,`Zm8=`,`Zm9v`,`Zm9vYg==`,`Zm9vYmE=`,`Zm9vYmFy`.
- Base64 decode round-trips (`Zm9vYmE=` → `fooba`, `Zm9vYmFy` → `foobar`).
- PEM `encode ("TEST","foobar")` exact text match, then `decode` recovers
  label `TEST` and der `666f6f626172`.
- PEM decode with CRLF line endings and surrounding explanatory text.
- 50-byte body PEM round-trip (exercises 64-column chunking).

15/15 PASS, `ALL PASS`.

## Files

- `cakeml/pem.sml` — ported library source (Base64 + Pem)
- `cakeml/pem_test.cml` — inlined source + vector driver
- `cakeml/pem_PORT_NOTES.md` — this file
