# AES — CakeML Port Notes

**Library:** sml-aes (FIPS 197)
**Scope ported:** AES block cipher core (`AesBlock`: key expansion + encrypt/decrypt
for AES-128/192/256) and `AesEcb` (single- and multi-block ECB).
**Not ported:** CBC, CTR, GCM modes — these layer on the same block core and
are left for a later layer.  The block cipher and ECB are enough to validate
correctness against the FIPS 197 Appendix B/C vectors.

## Outcome

| Criterion | Result |
|---|---|
| Ported to CakeML subset | yes — `cakeml/aes.sml`, `cakeml/aes_test.cml` |
| Compiles with CakeML v3400 | yes |
| AES-128 encrypt (FIPS 197 App. B) | PASS — `69c4e0d86a7b0430d8cdb78070b4c55a` |
| AES-128 decrypt (roundtrip) | PASS |
| AES-256 encrypt (FIPS 197 App. C) | PASS — `8ea2b7ca516745bfeafc49904b496089` |
| AES-256 decrypt (roundtrip) | PASS |
| AES-128/256 ECB roundtrip | PASS |

## Dialect-gap changes

Reuses the SHA-256/ChaCha20 `Word32`-via-`Word64` shim.  AES-specific gaps:

1. **No records.** CakeML has no SML records (`{nr, w}`).  The `key` type
   changed from `{ nr : int, w : Word32.word array }` to a tuple
   `(int, Word64.word Array.array)`; all `{nr, w}` patterns became
   `(nr, w)`.  This is the biggest structural change in the port.

2. **`Word8` literals need `Word8.fromInt`.** CakeML word literals
   (`0wx...`, `0w...`) are **always** `Word64.word`; there is no
   `0wx... : Word8.word` form (annotation is ignored — the literal is
   still `Word64`).  Every `Word8` literal in the original
   (`0wx80`, `0wx1b`, `0w2`, `0w3`, `0w9`, `0w11`, `0w13`, `0w14`, `0w0`, ...)
   became `Word8.fromInt <n>`.  This is pervasive in `xt`, `gm`, and
   `mixC`/`mixCi`.

3. **No `<>` on `Word8`.** The basis has `Word8.=` but no `Word8.<>`.
   `Word8.andb b 0wx80 <> 0w0` became
   `not (Word8.= (Word8.andb b (Word8.fromInt 0x80)) (Word8.fromInt 0))`.

4. **`0wFF` (no `x`) is a parse error.** Must be `0wxFF` (with the `x`
   prefix).  CakeML rejects `0wFF` outright — the lexer treats it as a
   malformed identifier.  (One occurrence in the test harness.)

5. **No `ListPair.zip`.** Use `List.zip` which takes a tuple
   (`List.zip ([0,1,2,3], xs)`).  Used in `setRow`.

6. **`Word32` → `Word64` + mask.** Same shim as before.  Key expansion's
   `Word32.<<`/`>>`/`xorb`/`orb` all go through `lsl32`/`lsr`/`xorb`/`orb`.

7. **Multi-clause `fun` rewritten.** The `gm` helper's
   `fun go 0 _ _ acc = acc | go n a b acc = ...` became
   `fun go n a b acc = if n <= 0 then acc else ...`.

8. **No signatures / `:> SIG`.** Dropped; the `local` block from the
   original was inlined directly into the structure (CakeML `local`
   works, but the shared utilities are simpler as plain structure
   members for the port).

9. **`true`/`false` → `True`/`False`; `SOME`/`NONE` → `Some`/`None`;
   `valOf` → `Option.valOf`; char comparisons use `Char.>=`/`Char.<=`.**
   Same as the ChaCha20 port (hex helpers in the test harness).

## Files

- `cakeml/aes.sml` — canonical port (`AesBlock` + `AesEcb` + `Hex`)
- `cakeml/aes_test.cml` — self-contained harness (inlines the structures)
- `cakeml/aes_PORT_NOTES.md` — this file
