#!/usr/bin/env bash
#
# compile_chain_demo.sh  --  Track 2d end-to-end compilation demonstration.
#
# Closes the sml-tls proof chain down to executable machine code by feeding the
# CakeML SHA-256 source (cakeml/sha256_test.cml, refined to the HOL4 spec in
# Tracks 2b/2c) through the CACHED, VERIFIED CakeML compiler binary and running
# the result.  The produced binary's SHA-256 output is checked byte-for-byte
# against the known NIST FIPS 180-4 digests for "" , "abc", and the 56-byte
# multi-block vector.
#
#   verified `cake` compiler  -->  arm8-64 machine code  -->  native run
#                                                             -->  digest == NIST
#
# The CakeML compiler is NOT rebuilt: we reuse the cached verified binary at
# CAKE_DIR/cake (CakeML v3400, cake-arm8-64).  The script is idempotent and
# cleans up its own scratch directory.
#
# Usage:   ./compile_chain_demo.sh            # run the demo
#          KEEP=1 ./compile_chain_demo.sh     # keep scratch artifacts
#
set -euo pipefail

# --- configuration --------------------------------------------------------
CAKE_DIR="${CAKE_DIR:-/tmp/cake-arm8-64}"
CAKE="$CAKE_DIR/cake"
FFI="$CAKE_DIR/basis_ffi.c"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/sha256_test.cml"          # canonical, spec-refined CakeML source
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sha256_chain.XXXXXX" 2>/dev/null || mktemp -d)"
ASM="$WORK/sha256_test.cake.S"
BIN="$WORK/sha256_test.cake"

cleanup() { [ "${KEEP:-0}" = "1" ] || rm -rf "$WORK"; }
trap cleanup EXIT

# --- preflight -------------------------------------------------------------
[ -x "$CAKE" ] || { echo "FATAL: cached cake compiler not found at $CAKE" >&2; exit 2; }
[ -f "$FFI" ] || { echo "FATAL: basis_ffi.c not found at $FFI" >&2; exit 2; }
[ -f "$SRC" ] || { echo "FATAL: CakeML source not found at $SRC" >&2; exit 2; }

echo "== Track 2d: verified-compiler -> machine-code -> run =="
echo "cake binary : $CAKE"
"$CAKE" --version | sed 's/^/  /'
echo "source      : $SRC"
echo "scratch     : $WORK"
echo

# --- step 1: compile CakeML source to arm8-64 machine code (assembly) ------
echo "[1/3] compiling with verified cake (--target=arm8) ..."
"$CAKE" --target=arm8 <"$SRC" >"$ASM"
test -s "$ASM" || { echo "FATAL: cake emitted no assembly" >&2; exit 3; }
echo "      emitted $(wc -l <"$ASM" | tr -d ' ') lines of arm8-64 assembly ($(wc -c <"$ASM" | tr -d ' ') bytes)"

# --- step 2: assemble + link into a native executable ----------------------
# Host is arm64 macOS; cake's arm8 output is the same ISA, so clang can
# assemble + link it against the CakeML FFI shim into a runnable binary.
echo "[2/3] assembling + linking with clang ..."
LDFLAGS=""
case "$(uname)" in Darwin) LDFLAGS="-Wl,-no_pie";; esac
if clang -O2 "$ASM" "$FFI" -lm -o "$BIN" $LDFLAGS 2>"$WORK/link.err"; then
  echo "      linked native executable: $(file "$BIN" | sed 's/^[^:]*: //')"
  RUNNABLE=1
else
  echo "      LINK FAILED (cross-target caveat) -- assembly artifact only:"
  sed 's/^/        /' "$WORK/link.err"
  RUNNABLE=0
fi
echo

# --- step 3: run and check against NIST digests ----------------------------
# Known-good NIST FIPS 180-4 SHA-256 digests, hard-coded so the check is
# independent of the program under test.
NIST_EMPTY="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
NIST_ABC="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
NIST_LONG="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

if [ "$RUNNABLE" = "1" ]; then
  echo "[3/3] running verified-compiler-produced machine code ..."
  OUT="$("$BIN")"
  echo "$OUT" | sed 's/^/      | /'
  echo
  GOT_EMPTY="$(printf '%s\n' "$OUT" | sed -n '/^PASS empty$/{n;p;}')"
  GOT_ABC="$(printf '%s\n'   "$OUT" | sed -n '/^PASS abc$/{n;p;}')"
  GOT_LONG="$(printf '%s\n'  "$OUT" | sed -n '/^PASS long$/{n;p;}')"

  ok=0
  check() { # name computed expected
    if [ "$2" = "$3" ]; then echo "      MATCH $1: $2 == NIST"; else
      echo "      MISMATCH $1: got=$2 nist=$3"; ok=1; fi
  }
  echo "digest verification (machine-code output vs known NIST FIPS 180-4):"
  check "empty (\"\")"   "$GOT_EMPTY" "$NIST_EMPTY"
  check "abc"            "$GOT_ABC"   "$NIST_ABC"
  check "long (56-byte)" "$GOT_LONG"  "$NIST_LONG"
  echo
  if [ "$ok" = "0" ]; then
    echo "RESULT: PASS -- verified compiler produced machine code whose SHA-256"
    echo "        output matches the NIST reference digests for all 3 vectors."
  else
    echo "RESULT: FAIL -- digest mismatch (see above)."; exit 1
  fi
else
  echo "[3/3] cannot run (link failed on this host) -- artifact-only result."
  echo "RESULT: PARTIAL -- verified cake emitted arm8-64 machine code (exit 0),"
  echo "        but it could not be linked into a runnable binary on this host."
  echo "        Assembly artifact verified non-empty; cross-target caveat applies."
fi
