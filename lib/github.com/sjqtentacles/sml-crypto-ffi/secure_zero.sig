(* secure_zero.sig

   Best-effort secure zeroing of sensitive byte buffers (Track 1b).

   `zero a` overwrites every byte of the Word8Array `a` with 0. The
   guarantee callers want is that the write is NOT elided by the optimizer
   as a dead store (the buffer is about to be dropped). There are two
   implementations selected at build time:

     - secure_zero_ffi.sml  : calls libsodium's sodium_memzero via the FFI
                              shim (the optimizer cannot elide it).
     - secure_zero_pure.sml : a portable Word8Array.modify fallback used
                              when the FFI shim is not linked (e.g. the
                              default `make test` / `make test-poly`).

   `zeroString s` is a convenience that returns an all-zero string of the
   same length as `s`, after wiping the temporary buffer it allocates.
   SML strings are immutable, so this cannot wipe `s` itself in place; it
   exists so callers can REPLACE a secret string field with zeros while
   still exercising the zeroing primitive on a buffer we own. *)

signature SECURE_ZERO =
sig
  (* True when this build is backed by the libsodium FFI memzero, false
     for the pure-SML fallback. Exposed so tests/docs can report which
     path is active. *)
  val ffiBacked : bool

  (* Overwrite every byte of `a` with 0. *)
  val zero : Word8Array.array -> unit

  (* Return an all-zero string the same length as `s`, wiping the scratch
     buffer used to build it. *)
  val zeroString : string -> string
end
