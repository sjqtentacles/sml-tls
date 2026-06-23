(* secret.sml

   The Word8Array-backed implementation of SECRET, used by BOTH the default
   (pure) and the FFI build. The only thing that differs between builds is
   the `SecureZero` structure linked ahead of this file in the .mlb:

     - default build: secure_zero_pure.sml  (Word8Array.modify fallback)
     - FFI build:     secure_zero_ffi.sml   (libsodium sodium_memzero)

   so this single source serves both. See secret.sig for the rationale and
   the honest `pinned`/`toBytes` residual notes. *)

structure Secret :> SECRET =
struct
  (* A secret is just a mutable byte array. Word8Array already has reference
     semantics: copying a `secret` value (e.g. threading a field forward
     through a functionally-rebuilt state record) copies the reference, so
     all copies share the one live buffer and a wipe through any handle is
     observed through every alias. *)
  type secret = Word8Array.array

  (* Not pinned: the bytes live in the ordinary GC heap. See secret.sig. *)
  val pinned = false

  val empty : secret = Word8Array.array (0, 0w0)

  fun fromString (s : string) : secret =
    Word8Array.tabulate
      (String.size s, fn i => Byte.charToByte (String.sub (s, i)))

  fun toBytes (a : secret) : string =
    CharVector.tabulate
      (Word8Array.length a, fn i => Byte.byteToChar (Word8Array.sub (a, i)))

  fun length (a : secret) : int = Word8Array.length a

  fun wipe (a : secret) : unit = SecureZero.zero a

  fun isWiped (a : secret) : bool =
    Word8Array.all (fn b => b = 0w0) a
end
