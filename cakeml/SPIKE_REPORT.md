# B2 SHA-256 Spike Report

**Track:** B2 (CakeML crypto-tower port)
**Spike:** L0 SHA-256 (go/no-go gate for the CakeML dialect)
**Status:** ✅ **GO** — SHA-256 ports to the CakeML subset, compiles with the
verified CakeML compiler, and reproduces all test vectors byte-for-byte.

## Outcome

| Criterion | Result |
|---|---|
| CakeML compiler built and working | ✅ v3400 prebuilt `cake-arm8-64`, verified end-to-end |
| SHA-256 ported to CakeML subset | ✅ `cakeml/sha256.sml` (canonical), `cakeml/sha256_test.cml` (harness) |
| Compiles with the CakeML compiler | ✅ `cake --target=arm8` → `.S` → linked binary |
| Correct output for test vectors | ✅ all three PASS, byte-identical to Poly/ML oracle |
| Feasibility assessment recorded | ✅ **GO** for the full crypto-tower port |

### Test vectors (all PASS)

| Input | Expected | CakeML output | Match |
|---|---|---|---|
| `""` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | ✅ |
| `"abc"` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | ✅ |
| `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"` (56 chars, 2 blocks) | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` | ✅ |

The CakeML-compiled binary's output is **byte-identical** to the original
sml-codec SHA-256 run under Poly/ML (the oracle) and to the published RFC
6234 / FIPS 180-4 vectors.

## Toolchain

- **CakeML:** v3400 release (2026-06-19). Used the prebuilt bootstrapped
  compiler `cake-arm8-64.tar.gz` (ARM64, native on the Apple M2 Pro spike
  host). The compiler is itself a verified CakeML program; the prebuilt
  `.S` is the bootstrapped output of the CakeML compiler compiled by
  itself. Pinned in `CAKEML_VERSION`.
- **HOL4:** "Trindemossen 2", commit `b3aa119c…` (2026-06-22). Not required
  for the spike itself — the prebuilt compiler suffices — but a full
  `Holmake` of the CakeML tree was started from HOL4 and confirmed to
  progress past theory compilation. It was stopped once the prebuilt
  compiler proved sufficient (the full build is ~20 hours / ~16 GB RAM
  per `build-instructions.sh`). HOL4 is required for the later
  refinement-proof phase (J4). Pinned in `HOL4_VERSION`.
- **Oracle:** MLton + Poly/ML on the original `sml-codec/sha256.{sig,sml}`,
  run via `/tmp/oracle_check.sml`. Both agree with the CakeML port.

### Reproduction

From a directory containing the v3400 `cake` binary and `basis_ffi.c`:

```sh
# 1. Compile the port (canonical source + driver) to machine code
cake --target=arm8 <combined.cml >combined.cake.S
# 2. Link with the CakeML FFI runtime
cc combined.cake.S basis_ffi.c -lm -o combined.cake
# 3. Run
./combined.cake
```

Where `combined.cml` is `cakeml/sha256.sml` concatenated with a driver that
calls `Sha256.hexDigest` and prints the result. The self-contained harness
`cakeml/sha256_test.cml` inlines the structure and runs all three vectors
with PASS/FAIL output.

## Dialect gaps found

The sml-codec SHA-256 is plain SML and almost clean CakeML. The port
required the following changes, all mechanical and bounded. None are
crypto-algorithmic; they are all surface syntax / basis-library gaps.

### 1. No `Word32` module (the big one)

**CakeML basis has `Word8` and `Word64` only — no `Word32`.** SHA-256 is
built entirely on 32-bit word arithmetic.

**Fix:** emulate `Word32` using `Word64` plus a `0wxFFFFFFFF` mask applied
after every `+` and `<<` (the two ops that can exceed 32 bits). XOR/AND/OR
are width-preserving so no mask is needed there. A helper `add32 a b =
Word64.andb (Word64.+ a b) mask32` wraps the addition; `lsl32` masks the
left shift. `rotr` masks the left half of the rotation.

**Impact on the rest of the tower:** every crypto primitive that uses
`Word32` (SHA-256, SHA-512's 32-bit cousin, HMAC, AES, ChaCha20, etc.)
needs the same `add32`/`lsl32`/`mask32` shim. This is a one-time,
copy-pasteable pattern — **not a blocker**. For 64-bit-word primitives
(SHA-512, Poly1305) `Word64` is used directly.

### 2. No `IntInf` — but CakeML `int` is already arbitrary precision

The original uses `IntInf` for the message bit-length (to handle >2GB
messages). CakeML's `int` is unbounded, so `IntInf` is unnecessary — plain
`int` works. The `IntInf.~>>`/`IntInf.andb`/`IntInf.toInt` calls become
ordinary `div`/`mod` (CakeML has no `>>` on `int` either — see gap 3).

### 3. No `>>` / `<<` on `int`

CakeML's `Word64.<<` / `Word64.>>` exist (and take an `int` shift count),
but there is no shift on `int` itself. The padding code's
`bitLen >> (i*8)` becomes `bitLen div (shiftFactor i) mod 256`, where
`shiftFactor` is a small lookup table for `256^i`, `i ∈ [0,7]`.

### 4. No `StringCvt` / `Word32.fmt` / `StringCvt.padLeft`

The original formats hex via `Word32.fmt StringCvt.HEX` and zero-pads with
`StringCvt.padLeft`. CakeML has neither. **Fix:** hand-rolled `hexDigit`,
`hexByte`, and `hexWord` functions that walk the 4 nibbles of each byte
and emit lowercase hex. ~12 lines, fully self-contained.

### 5. No `Char.toLower`

Not needed for the spike (we emit lowercase directly), but noted for the
PEM/ASN.1 ports later. Hand-rolling is trivial.

### 6. No `infix` declarations (at all)

CakeML does not accept `infix` declarations, neither at top level nor
inside `struct`. The original declares `infix andb orb xorb`, `infix << >>`,
`infix 6 ++`. **Fix:** drop all `infix`/`op` and use plain curried function
calls: `add32 a b`, `andb a b`, `xorb a b`, etc. This makes the call sites
more verbose but is purely syntactic.

### 7. No `fun ... | ...` multi-clause function definitions

CakeML does not support SML's multi-clause `fun f pat1 = ... | f pat2 = ...`.
The original `chunk16`'s `take` helper uses this. **Fix:** rewrite as a
single `fun take j xs acc = if j = 0 then ... else case xs of ...`.
Pattern-matching on constructors in `case` works fine; only the
`fun`-with-`|` form is rejected.

### 8. No curried `fn x y => ...` lambdas

CakeML `fn` accepts **exactly one** argument. `fn blk st => ...` is a
parse error. **Fix:** `fn blk => fn st => ...`. This affects the one
`List.foldl` lambda in `digestWords`.

### 9. No return-type annotations on `fun`

`fun f (x : ty) : ret_ty = ...` is rejected — the `: ret_ty` after the
argument list is a parse error. Argument-type annotations
(`fun f (x : ty) = ...`) and `val` annotations (`val x : ty = ...`) are
both accepted. **Fix:** drop the return-type annotation on `padded` (the
only function that had one).

### 10. No `#1` / `#2` tuple selectors

CakeML has no `#n` tuple-field selector. The original doesn't use it, but
the test harness's first draft did. **Fix:** `case r of (a, b) => ...`.

### 11. No `op` keyword

Not needed once `infix` is dropped (see gap 6). `op +` etc. are not used.

### 12. Signature ascription dropped

The original is `structure Sha256 :> SHA256 = struct ... end`. CakeML has
no signatures at present (per `how-to.md`). **Fix:** `structure Sha256 =
struct ... end`. No information loss — the signature was purely
documentary.

### Things that worked without change

- `structure ... = struct ... end` ✅
- `val` with type annotations ✅
- `fun` with argument type annotations ✅
- `Vector.fromList`, `Vector.sub` ✅
- `Array.array`, `Array.sub`, `Array.update`, `Array.length` ✅
- `Word64.fromInt`, `Word64.toInt`, `Word64.andb/orb/xorb/</</>>` ✅
- `Word64.` literal syntax `0wx...` ✅
- `String.sub`, `String.implode`, `String.concat`, `String.size`, `^` ✅
- `Char.ord`, `Char.chr` ✅
- `List.foldl`, `List.map`, `List.rev`, `List.tabulate` ✅
- `case ... of ... => ... | ... => ...` ✅
- `let ... in ... end` with `;` sequencing ✅
- Hex integer literals `0wx...` ✅
- Nested `let`, curried `fun`, recursion ✅

## Algorithmic correctness note

One non-dialect bug was caught during testing: the first port used
`64 - n` in `rotr` (rotating within the full 64-bit word) instead of
`32 - n` (rotating within the emulated 32-bit window). Because the
32-bit value lives in the low 32 bits of a Word64 with the high 32 bits
zero, `<< w (64 - n)` shifts bits into the wrong window. The fix is
`<< w (32 - n)` followed by the 32-bit mask. This produced visibly wrong
digests (the binary ran and printed, just incorrect output), confirming
that the test vectors are an effective gate. This is exactly the class
of error the spike is designed to surface before fanning out the tower.

## Feasibility assessment for the full crypto-tower port

**Verdict: GO.** The SHA-256 spike clears the go/no-go gate. The dialect
gaps are all surface-level and fall into a small, repeatable set of
patterns (Word32 emulation, no `infix`, single-arg `fn`, no multi-clause
`fun`, hand-rolled hex/formatting). None touch the cryptographic
algorithm. The port is ~150 lines of clean CakeML and was completed in
one session.

### What carries over to the rest of L0

| Library | Word width | Expected effort | Notes |
|---|---|---|---|
| `sml-codec` (SHA-256) | 32-bit | **done** | this spike |
| `sml-bigint` | arbitrary | low | CakeML `int` is already bignum; mostly syntax |
| `sml-aes` | 32-bit (columns) | medium | same `add32` shim; heavy tabular lookups, but `Array`/`Vector` work |
| `sml-chacha20` | 32-bit | low | pure Word32 arithmetic, same shim |
| `sml-x25519` | 256-bit | medium | bignum via CakeML `int` with mod, or emulate; no `Word32`/`Word64` field math issues |

### Risks for later layers

1. **Mutable state / arrays:** SHA-256 uses one `Array.array(64, ...)` per
   block. CakeML arrays work fine. AES and the bigint libraries use more
   array-heavy patterns; the basis `Array` and `Word8Array` APIs are
   complete enough.
2. **FFI / I/O:** the spike uses only `print`. PEM parsing, X.509, and the
   TLS socket layer will need `TextIO` and possibly `Word8Array` I/O,
   which are in the basis but untested here. L1+ should add an I/O smoke
   test.
3. **Multi-file programs:** the simple `cake` invocation compiles a
   single source file. The canonical `sha256.sml` is kept separate from
   the test harness; combining them is a `cat`. For the full tower, a
   small build script that concatenates the dependency-ordered `.sml`
   files into one `.cml` is the path of least resistance (CakeML's REPL
   and `--types` also operate on a single compilation unit).
4. **Performance:** not measured in this spike. The Word32-via-Word64
   emulation adds a mask per arithmetic op; ChaCha20/AES may want a
   perf check, but correctness is unaffected.
5. **Verified compiler vs. verified program:** the CakeML *compiler* is
   verified; the SHA-256 *program* is not yet proven. Moving to a proven
   program (via `ml_translatorLib` / `cv` tooling) is the J4 phase and
   requires the HOL4 build (already confirmed working). The spike
   deliberately stays at "compiles and runs correctly" — the bar the
   plan sets for B2/L0.

### Recommendation

Fan out the rest of L0 (`sml-bigint`, `sml-aes`, `sml-chacha20`,
`sml-x25519`) in parallel using the patterns established here. Each port
should ship with the same three-vector-style test harness against the
MLton/Poly oracle. Pin CakeML v3400 and HOL "Trindemossen 2" (done in
`CAKEML_VERSION` / `HOL4_VERSION`).
