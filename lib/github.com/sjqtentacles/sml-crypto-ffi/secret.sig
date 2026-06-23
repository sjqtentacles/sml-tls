(* secret.sig

   A mutable, reference-shared secret-byte buffer (Track 1b core).

   The whole point is REAL in-place erasure. SML strings are immutable, so a
   `string`-typed secret field can only ever be REBOUND to a fresh all-zero
   string -- the original bytes (and any GC copies) live on, and erasing
   through one alias is invisible to another. A `secret` instead wraps a
   MUTABLE `Word8Array.array` with reference semantics: every value that was
   copied from a given `secret` shares the SAME underlying array, so
   `wipe`-ing through any one handle zeroes the bytes that EVERY alias sees.

   This is what makes the zeroize tests meaningful: the test captures a
   handshake state, zeroizes the (functionally rebuilt) state, and then reads
   the secrets back through the ORIGINAL state handle -- they read as all
   zero, because both states share the same live buffers.

   The wipe itself is delegated to `SecureZero.zero`, whose implementation is
   selected at build time: `sodium_memzero` via the FFI shim in the FFI build
   (a wipe the C optimizer is guaranteed not to elide), or a portable
   `Word8Array.modify` fallback in the default build. So the same `Secret`
   source serves both builds; only the linked `SecureZero` differs.

   `pinned` reports whether the backing bytes live in non-swappable,
   non-relocatable memory (e.g. libsodium `sodium_malloc` + `sodium_mlock`).
   The current implementation does NOT pin: holding a raw C pointer alive
   across the purely-functional state threading is fragile and divergent on
   MLton vs Poly/ML, and every crypto primitive copies the bytes into a GC'd
   string at the call boundary anyway (see `toBytes`). Pinning is therefore
   documented as a residual via `pinned = false` rather than half-implemented.

   All byte material is the raw byte-string convention used across the
   sjqtentacles crypto family (one char per byte, 0-255). *)

signature SECRET =
sig
  (* Opaque, MUTABLE, reference-shared secret buffer. *)
  type secret

  (* True iff the backing store is pinned/locked (sodium_malloc + mlock).
     False for the Word8Array-backed implementation used on both builds. *)
  val pinned : bool

  (* A fresh zero-length secret. *)
  val empty : secret

  (* Copy `s` into a fresh mutable buffer. The argument string is NOT (and
     cannot be) wiped -- callers that derived `s` from a transient should
     drop their reference and let GC reclaim it. *)
  val fromString : string -> secret

  (* Materialize the current bytes as a string, for handing to a
     byte-oriented crypto primitive. NOTE (honest residual): this allocates a
     transient GC'd string that we cannot reliably wipe, and the crypto API
     copies it again internally; this transient copy is the boundary limit of
     the approach short of rewriting every primitive to take `secret`. *)
  val toBytes : secret -> string

  (* Length in bytes (preserved by `wipe`). *)
  val length : secret -> int

  (* Overwrite every byte of the backing buffer with 0, IN PLACE, via
     SecureZero.zero. Every alias of this secret observes the wipe. Idempotent
     and safe to call on `empty`. *)
  val wipe : secret -> unit

  (* True iff every byte of the backing buffer is currently 0. (A zero-length
     secret is vacuously wiped.) *)
  val isWiped : secret -> bool
end
