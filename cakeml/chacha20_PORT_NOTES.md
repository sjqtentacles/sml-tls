# ChaCha20 — CakeML Port Notes

**Library:** sml-chacha20 (RFC 8439)
**Scope ported:** ChaCha20 block function + encrypt/decrypt (the stream cipher).
**Not ported:** Poly1305 MAC and the ChaCha20-Poly1305 AEAD construction —
these need CakeML `int` bignum arithmetic and were left for a later layer to
keep the L0 gate tight. XChaCha20 likewise depends on the block function and
can be layered on later.

## Outcome

| Criterion | Result |
|---|---|
| Ported to CakeML subset | yes — `cakeml/chacha20.sml`, `cakeml/chacha20_test.cml` |
| Compiles with CakeML v3400 | yes (`cake --target=arm8` → `.S` → linked binary) |
| RFC 8439 §2.3.2 block vector | PASS (byte-identical) |
| RFC 8439 §2.4.2 encrypt vector | PASS (byte-identical, 114-byte plaintext) |
| encrypt/decrypt roundtrip | PASS |

## Dialect-gap changes

The port reuses the SHA-256 spike's `Word32`-via-`Word64`+`mask32` shim
verbatim (`add32`, `lsl32`, `lsr`, `andb`, `orb`, `xorb`).  The
algorithmic body is otherwise a direct transliteration.  Specific gaps
hit beyond the spike:

1. **`ref` → `Ref`.** CakeML's basis exposes the reference constructor
   as `Ref` (not `ref`); `!` and `:=` work as in SML.  The quarter-round
   (`qr`) and the block state both use `Word64.word ref` cells, so every
   `ref` in the original became `Ref`.

2. **Multi-clause `fun` rejected.** The original's
   `fun go 0 _ _ acc = acc | go n a b acc = ...` (in the AES `gm` helper,
   not present in the ChaCha20 core) and my first port's
   `fun doRounds 0 = () | doRounds n = ...` both fail to parse.  Rewritten
   as `fun doRounds n = if n <= 0 then () else (doubleRound (); doRounds (n-1))`.

3. **`true`/`false` → `True`/`False`.** (Not exercised by the ChaCha20
   core itself, but the hex helpers and test driver use `True`/`False`.)

4. **`SOME`/`NONE` → `Some`/`None`; `valOf` → `Option.valOf`.** CakeML
   constructors are capitalised; `Some`/`None` are the option
   constructors.  `valOf` is not a top-level binding — use `Option.valOf`.

5. **Char comparisons need `Char.>=` / `Char.<=` (curried).** The
   top-level `>=`/`<=` default to `int -> int -> bool`; CakeML has no
   equality types, so the overloading does not resolve to `char`.  The
   hex decoder's `c >= #"0"` became `Char.>= c #"0"`.

6. **No SML `\` line-continuation in string literals.** The RFC test
   vectors are long hex strings; the original SML used `"...long...\\n\
   \...rest..."` to split them across lines.  CakeML rejects this —
   rewritten as explicit `"..." ^ "..."` concatenation.

7. **No `Word32` module.** Same as the SHA-256 spike — all 32-bit word
   arithmetic is emulated on `Word64` with `0wxFFFFFFFF` masking after
   `+` and `<<`.  `rotl32` is `orb (lsl32 x n) (lsr x (32 - n))`.

8. **No signatures / `:> SIG`.** Dropped; the structure is
   `structure ChaCha20 = struct ... end`.

## Test-vector note (non-bug)

The first port used the §2.3.2 block-test nonce
(`000000090000004a00000000`) for the §2.4.2 encryption test as well.
RFC 8439 §2.4.2 actually uses a **different** nonce
(`000000000000004a00000000` — the first 4 bytes are zero, not `09`).
The block function was correct (the block vector passed first try); the
encrypt vector failed only because of the wrong nonce in the harness.
Fixed by using the §2.4.2 nonce for the encryption test.  This is the
same class of error the spike report flagged: the vectors are an
effective gate, catching test-harness mistakes that a self-consistent
roundtrip would not.

## Files

- `cakeml/chacha20.sml` — canonical port (block + encrypt/decrypt + hex helpers)
- `cakeml/chacha20_test.cml` — self-contained harness (inlines the structure)
- `cakeml/chacha20_PORT_NOTES.md` — this file
