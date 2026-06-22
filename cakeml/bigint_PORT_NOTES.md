# sml-bigint → CakeML Port Notes

## Summary

Ported `sml-bigint` (arbitrary-precision signed integers) to the CakeML subset.
All core operations compile and pass test vectors: `fromInt`, `toString`,
`fromString`, `add`, `sub`, `mul`, `divMod`, `compare`, `pow`, `gcd`, `isqrt`,
`modpow`, `toInt`.

## Dialect-gap fixes applied

1. **No `Word32`** — emulated via `Word64` + `0wxFFFFFFFF` mask (`add32`,
   `lsl32`, etc.).
2. **No `Word64.*` (multiplication)** — CakeML's `Word64` module exposes no
   multiplication operator. Implemented `mul32c` via `Word64.toInt` → `int *`
   → `Word64.fromInt` (CakeML `int` is arbitrary-precision, so no overflow).
3. **No return-type annotations on `fun`** — stripped all `: type` annotations
   from `fun` declarations.
4. **No argument type annotations on `fun`** — stripped all `: type`
   annotations from `fun` arguments (e.g., `fun f (a : mag) =` → `fun f (a) =`).
5. **`EQUAL`/`GREATER`/`LESS` → `Equal`/`Greater`/`Less`** — CakeML uses
   capitalized ordering constructors.
6. **`Int.max`/`Int.min` not available** — replaced with inline
   `if a >= b then a else b`.
7. **`abs` not available** — replaced with inline `if n < 0 then ~n else n`.
8. **`#1`/`#2` tuple selectors not supported** — replaced with
   `let val (a, _) = ... in a end`.
9. **`op~`/`op+`/`op-`/`op*` rebindings not supported** — removed; callers use
   named functions (`negate`/`add`/`sub`/`mul`) directly.
10. **`datatype` with `of`** — `datatype bigint = BI of int * mag` →
    `datatype bigint = BI int mag` (Haskell-style, curried constructor).
11. **Constructor application** — `BI (sgn, m)` → `BI sgn m` (curried).
12. **`exception FailMsg of string`** — CakeML uses `exception Name type`
    (no `of`).
13. **`IntInf` dropped** — CakeML `int` is already arbitrary-precision.
14. **`handle Overflow` dropped** — CakeML `int` never overflows.
15. **`Vector.tabulate (n, fn)`** — CakeML's `Vector.tabulate` is curried:
    `Vector.tabulate n (fn ...)`.
16. **Tuple-form function calls** — several functions defined as
    `fun f (a, b) =` were called curried (`f a b`); fixed to `f (a, b)`.
17. **`Domain` exception** — defined locally (`exception Domain`).
18. **`~s` in constructor** — `BI ~s m` parsed as 3 args; wrapped as
    `BI (~s) m`.

## Algorithmic note on `mul32c`

The original used `Word64.*` for 32×32→64 multiplication. Since CakeML's
`Word64` has no multiplication, `mul32c` computes the product via `int`:

```sml
fun mul32c a b =
  let val ai = Word64.toInt a
      val bi = Word64.toInt b
      val prod = ai * bi
  in (Word64.andb (Word64.fromInt prod) mask32, Word64.>> (Word64.fromInt prod) 32) end
```

In `magMulSchool`, the carry propagation was adjusted: the high 32 bits of
the product (`phi`) are added to the carry, not to the current limb.

## Test vectors

- `fromInt`/`toString`: 0, 1, ~1, 12345, ~12345
- `fromString`: 30-digit number, negative number
- `add`: 123456789012345678901234567890 + 987654321098765432109876543210
- `sub`: 987654321098765432109876543210 - 123456789012345678901234567890
- `mul`: 30-digit × 30-digit (60-digit result)
- `divMod`: 30-digit ÷ 1000000
- `compare`: <, >, =
- `pow`: 2^64
- `gcd`: gcd(48, 36) = 12
- `isqrt`: 99→9, 100→10, 101→10
- `modpow`: 2^100 mod 1000000007 = 976371285
- `toInt`: 42 roundtrip

All pass.

## Files

- `cakeml/bigint.sml` — ported library source
- `cakeml/bigint_test.cml` — inlined source + test driver
- `cakeml/bigint_PORT_NOTES.md` — this file
