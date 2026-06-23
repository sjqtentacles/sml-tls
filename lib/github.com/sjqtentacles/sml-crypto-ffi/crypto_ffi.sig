(* crypto_ffi.sig

   Constant-time crypto via an FFI shim over libsodium (Track 1a/1b).

   This signature is implemented twice -- once with MLton's `_import`
   (crypto_ffi_mlton.sml) and once with Poly/ML's `Foreign` structure
   (crypto_ffi_poly.sml) -- so the same `CryptoFfi` structure is available
   on both compilers. Each build selects exactly one implementation file.

   The interface intentionally mirrors the SHAPE of the pure-SML modules it
   replaces so it can be used as a near drop-in:

     - `dh` / `base`            match X25519.dh / X25519.base
     - `seal` / `open'`         match Aead.seal / Aead.open' for
                                ChaCha20-Poly1305 (record-form: ct||tag)
     - `memzero`                best-effort secure wipe (Track 1b)

   All byte material is RAW byte strings (one char per byte, 0-255), the
   same convention as the rest of the sjqtentacles crypto family. *)

signature CRYPTO_FFI =
sig
  (* Raised on a length/contract violation or an underlying libsodium error
     (distinct from an AEAD authentication failure, which is `NONE`). *)
  exception CryptoFfi of string

  (* Idempotent libsodium initialisation. The implementations call this
     lazily on first use, but it is exposed for explicit warm-up/tests. *)
  val init : unit -> unit

  (* X25519 (RFC 7748). `scalar` and `point` are 32-byte little-endian
     strings; the result is the 32-byte shared u-coordinate. libsodium
     clamps the scalar internally, matching X25519.dh. *)
  val dh   : string -> string -> string

  (* Public key: dh scalar 9. 32-byte little-endian result. *)
  val base : string -> string

  (* 32, for symmetry with X25519.keySize. *)
  val keySize : int

  structure ChaCha20Poly1305 :
  sig
    (* seal key nonce aad plaintext -> ciphertext || 16-byte tag.
       `key` is 32 bytes, `nonce` is 12 bytes. Raises CryptoFfi on a
       length violation. *)
    val seal  : string -> string -> string -> string -> string

    (* open' key nonce aad (ciphertext||tag) -> SOME plaintext | NONE.
       NONE iff the tag does not verify or the input is too short. *)
    val open' : string -> string -> string -> string -> string option
  end

  (* Overwrite the bytes currently held by a Word8Array using libsodium's
     sodium_memzero, which the optimizer may not elide (Track 1b). *)
  val memzero : Word8Array.array -> unit
end
