# X25519 — CakeML Port Notes

**Library:** sml-x25519 (RFC 7748)
**Scope ported:** X25519 scalar multiplication (`dh`, `base`, `clamp`, `toHex`,
`fromHex`).  This is the complete public surface of the original library.

## Outcome

| Criterion | Result |
|---|---|
| Ported to CakeML subset | yes — `cakeml/x25519.sml`, `cakeml/x25519_test.cml` |
| Compiles with CakeML v3400 | yes |
| RFC 7748 §5.2 vector 1 (scalar `a546...`, u-coord `e6db...`) | PASS — `c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552` |
| RFC 7748 §5.2 vector 2 (scalar `4b66...`, u-coord `e521...`) | PASS — `95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957` |

Both vectors passed on the first successful compile — the algorithmic body
is a direct transliteration of the Montgomery ladder; only the surface
syntax and the `IntInf`-to-`int` translation were changed.

## Dialect-gap changes

X25519 is the cleanest port of the four because the original is already
written in a high-level, bignum-heavy style that maps naturally onto
CakeML's arbitrary-precision `int`.  No `Word32` shim is needed (the field
is GF(2^255 - 19), well beyond 32/64 bits).  Specific gaps:

1. **`IntInf` → `int`.** CakeML's `int` is unbounded (the `how-to.md`
   factorial example confirms this), so every `IntInf.int` becomes `int`,
   `IntInf.fromInt n` becomes `n`, and `IntInf.toInt n` becomes `n`.
   No overflow risk: the intermediate products in the Montgomery ladder
   are at most ~(2^255)^2 = 2^510, well within bignum range.

2. **No bitwise ops on `int`.** CakeML `int` has `+`, `-`, `*`, `div`,
   `mod`, comparisons — but no `andb`/`orb`/`xorb`/`<<`/`~>>` (those are
   only on `Word8`/`Word64`).  The original uses `IntInf.andb`/`~>>` for
   bit extraction in `leEncode`, `fpow`, and the ladder's per-bit scalar
   walk.  All replaced with arithmetic:
   - `IntInf.andb (e, 1)` → `e mod 2`
   - `IntInf.~>> (k, t)` (for bit `t`) → `(k div pow2 t) mod 2`
   - `IntInf.~>> (n, 8*i)` (byte `i`) → `(n div pow2 (8*i)) mod 256`
   where `pow2 n` is a small recursive helper (`2 * pow2 (n-1)`).

3. **Byte-level bitwise still uses `Word8`.** The `clamp` and
   `decodeUCoordinate` functions mask/merge individual bytes; those use
   `Word8.andb`/`Word8.orb` on `Word8.word` (built from `Word8.fromInt`
   — see the AES notes: CakeML word literals are always `Word64`, so
   `Word8` constants need `Word8.fromInt`).

4. **`CharVector.tabulate` → `String.implode` o `List.tabulate`.** CakeML
   has no `CharVector` structure; `String.implode` + `List.tabulate` is
   the equivalent.

5. **Exception syntax is Haskell-style.** `exception FailMsg string`
   (no `of`) — CakeML drops the `of` keyword in exception declarations.
   The original's `raise Fail "msg"` (using the built-in `Fail`)
   became `raise FailMsg "msg"` with a local `exception FailMsg string`
   to avoid depending on the basis `Fail` exception (which may or may
   not exist in CakeML — the local exception is safer and
   self-documenting).

6. **No signatures / `:> SIG`.** Dropped.

7. **`true`/`false` → `True`/`False`; `SOME`/`NONE` → `Some`/`None`;
   `valOf` → `Option.valOf`; char comparisons use `Char.>=`/`Char.<=`.**
   Same as the other ports (hex helpers and test harness).

## Performance note

The `pow2 t` helper is called inside the ladder loop (255 iterations),
and each call recomputes `2^t` from scratch (O(t) multiplications).
This is O(n^2) for the ladder where the original was O(n).  For the
test vectors (which run instantly) this is fine, but a production port
would precompute a `pow2` table or shift the scalar right by one bit
per iteration instead.  Correctness is unaffected; this is a perf
optimisation for later.

## Files

- `cakeml/x25519.sml` — canonical port (full X25519 surface)
- `cakeml/x25519_test.cml` — self-contained harness (inlines the structure)
- `cakeml/x25519_PORT_NOTES.md` — this file
