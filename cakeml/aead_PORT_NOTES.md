# sml-aead → CakeML Port Notes

## Summary

Ported `sml-aead` (the algorithm-agnostic AEAD facade) plus the primitives it
dispatches to, so the facade is actually exercisable end-to-end:

- **ChaCha20** (RFC 8439 stream cipher) — reused from `cakeml/chacha20.sml`.
- **Poly1305** (RFC 8439 one-time MAC) — re-implemented with CakeML native-int
  bignum field arithmetic (the original used `IntInf`).
- **ChaCha20Poly1305** (RFC 8439 §2.8 AEAD) — new.
- **AesBlock** (FIPS 197) — reused from `cakeml/aes.sml`.
- **AesCtr** + **AesGcm** (NIST GCM, GHASH) — new.
- **Aead** facade — `seal`/`open'` dispatch on an `alg` tag.

All compile with the pinned `cake` v3400 and reproduce the standard AEAD test
vectors byte-for-byte (RFC 8439 §2.8.2 ChaCha20-Poly1305; McGrew/NIST GCM
test cases 3, 4, 15 for AES-128/256-GCM), including authenticated `open` and a
tamper→`None` check.

## Dialect-gap fixes applied

1. **Records → tuples.** The facade API `seal alg {key, nonce, aad, plaintext}`
   / `open' alg {key, nonce, aad, ciphertext}` became
   `seal alg (key, nonce, aad, plaintext)` /
   `open' alg (key, nonce, aad, ciphertext)`.
2. **Constructor/structure name clash.** The original `datatype alg`
   constructor `ChaCha20Poly1305` collides with the *structure*
   `ChaCha20Poly1305` (both must be uppercase in CakeML). Renamed the
   constructors `AChaCha20Poly1305 | AAesGcm128 | AAesGcm256`.
3. **`IntInf` → native `int`.** Poly1305's `p = 2^130 − 5`, the per-block
   accumulate `acc = ((acc + n) · r) mod p`, and the final
   `tag = (acc + s) mod 2^128` use CakeML's arbitrary-precision `int`
   directly. There is **no `<<`/`andb`/`orb` on `int`** in CakeML, so:
   - `loadLE` (which ORs in `2^(8·len)`) became
     `leInt(...) + pow2 (8·len)` (the low bits are always zero there, so OR = +).
   - `clamp r` (a 128-bit `andb` with `0x0ffffffc…`) was pushed down to the
     **byte level**: clear the low nibble of bytes 3/7/11/15 (`v mod 16`) and
     the low two bits of bytes 4/8/12 (`v − v mod 4`) before assembling `r`.
   - `tag mod 2^128` replaces `andb (…, 2^128−1)`; per-byte extraction uses
     `(tag div pow2 (8·i)) mod 256`.
   A single top-level `fun pow2 n` is shared by Poly1305, ChaCha20Poly1305
   (the `le64` length tag) and AES-GCM (`be64`).
4. **`List.foldl` is curried element-then-accumulator.** GHASH's
   `List.foldl (fn (i, y) => …) init blocks` became
   `List.foldl (fn i => fn y => …) init blocks`.
5. **Word8 shifts take an `int`, not `Word.word`.** `Word8.>> (w, Word.fromInt k)`
   → `Word8.>> w k`; `Word8.<< (w, 0w7)` → `Word8.<< w 7`. Same for the GF(2^128)
   shift/reduce in `ghashMul`.
6. **No `<>` on `Word8`.** `Word8.andb (…) <> 0w0` → a helper
   `isSet w = not (Word8.= w (Word8.fromInt 0))`.
7. **Tupled basis calls made curried** (`String.sub`, `String.substring`,
   `Array.array`, `Array.tabulate`, `Array.sub`, `Array.update`,
   `List.tabulate`, `List.zip` stays tupled per its signature).
8. **`ref`/`SOME`/`NONE` → `Ref`/`Some`/`None`**; `op ::` in `Array.foldr`
   → `fn x => fn xs => x :: xs`.
9. **No return-type / argument-type annotations on `fun`** (stripped, e.g.
   `((nr, w) : key)` → `((nr, w))`).
10. **No signature ascription.**

## Algorithmic confirmation

The McGrew GCM test vectors and RFC 8439 ChaCha20-Poly1305 vector are exact
oracles: the GF(2^128) bit-shift reduction, the `J0 = IV ‖ 0x00000001`
construction, the CTR start at `inc(J0)`, the GHASH length block (big-endian
bit-lengths) and the Poly1305 clamp all had to be byte-correct to match.

## Test vectors (all PASS)

| Vector | seal | open |
|---|---|---|
| RFC 8439 §2.8.2 ChaCha20-Poly1305 | ✅ ct‖tag match | ✅ + tamper→None |
| AES-128-GCM TC3 (no AAD, 64B) | ✅ | ✅ |
| AES-128-GCM TC4 (20B AAD, 60B) | ✅ | ✅ |
| AES-256-GCM TC15 (no AAD, 64B) | ✅ | ✅ |

9/9 PASS, `ALL PASS`.

## Files

- `cakeml/aead.sml` — ported library (ChaCha20/Poly1305/ChaCha20Poly1305/
  AesBlock/AesCtr/AesGcm/Aead)
- `cakeml/aead_test.cml` — inlined source + RFC/NIST vector driver
- `cakeml/aead_PORT_NOTES.md` — this file
