(* crypto_ffi_mlton.sml

   MLton implementation of CRYPTO_FFI using `_import` to call the libsodium
   shim (lib/.../sml-crypto-ffi/shim.c). The shim object/library is linked
   into the executable by the Makefile via `-link-opt`.

   This file uses MLton-only `_import` syntax and is NOT loaded under
   Poly/ML (which uses crypto_ffi_poly.sml instead). *)

structure CryptoFfi :> CRYPTO_FFI =
struct
  exception CryptoFfi of string

  val keySize = 32

  (* --- libsodium shim imports (see shim.c) --- *)
  val cInit = _import "sml_sodium_init" public : unit -> int;
  val cX25519 = _import "sml_x25519" public :
    Word8Array.array * Word8Array.array * Word8Array.array -> int;
  val cX25519Base = _import "sml_x25519_base" public :
    Word8Array.array * Word8Array.array -> int;
  val cSeal = _import "sml_chacha20poly1305_seal" public :
    Word8Array.array * Word8Array.array * int
    * Word8Array.array * int * Word8Array.array * Word8Array.array -> int;
  val cOpen = _import "sml_chacha20poly1305_open" public :
    Word8Array.array * Word8Array.array * int
    * Word8Array.array * int * Word8Array.array * Word8Array.array -> int;
  val cMemzero = _import "sml_memzero" public :
    Word8Array.array * int -> unit;

  (* --- byte string <-> Word8Array marshalling --- *)
  fun toArr (s : string) : Word8Array.array =
    Word8Array.tabulate (String.size s,
      fn i => Byte.charToByte (String.sub (s, i)))

  fun fromArr (a : Word8Array.array) : string =
    CharVector.tabulate (Word8Array.length a,
      fn i => Byte.byteToChar (Word8Array.sub (a, i)))

  val initialised = ref false
  fun init () =
    if !initialised then ()
    else
      let val r = cInit () in
        if r < 0 then raise CryptoFfi "sodium_init failed"
        else initialised := true
      end

  fun checkLen (what, s, n) =
    if String.size s <> n then
      raise CryptoFfi (what ^ " must be " ^ Int.toString n ^ " bytes, got "
                       ^ Int.toString (String.size s))
    else ()

  fun dh scalar point =
    ( init ()
    ; checkLen ("scalar", scalar, 32)
    ; checkLen ("point", point, 32)
    ; let
        val out = Word8Array.array (32, 0w0)
        val _ = cX25519 (out, toArr scalar, toArr point)
        (* A zero result (small-order point) returns -1; the pure-SML
           oracle just returns the zero output, so we mirror that and
           return the (zeroed) output rather than raising. *)
      in fromArr out end )

  fun base scalar =
    ( init ()
    ; checkLen ("scalar", scalar, 32)
    ; let
        val out = Word8Array.array (32, 0w0)
        val _ = cX25519Base (out, toArr scalar)
      in fromArr out end )

  structure ChaCha20Poly1305 =
  struct
    fun seal key nonce aad plaintext =
      ( init ()
      ; checkLen ("key", key, 32)
      ; checkLen ("nonce", nonce, 12)
      ; let
          val m = toArr plaintext
          val ad = toArr aad
          val out = Word8Array.array (String.size plaintext + 16, 0w0)
          val n = cSeal (out, m, String.size plaintext,
                         ad, String.size aad, toArr nonce, toArr key)
        in
          if n < 0 then raise CryptoFfi "chacha20poly1305 seal failed"
          else fromArr out
        end )

    fun open' key nonce aad sealed =
      ( init ()
      ; checkLen ("key", key, 32)
      ; checkLen ("nonce", nonce, 12)
      ; if String.size sealed < 16 then NONE
        else
          let
            val c = toArr sealed
            val ad = toArr aad
            val out = Word8Array.array (String.size sealed - 16, 0w0)
            val n = cOpen (out, c, String.size sealed,
                           ad, String.size aad, toArr nonce, toArr key)
          in
            if n < 0 then NONE else SOME (fromArr out)
          end )
  end

  fun memzero a =
    ( init (); cMemzero (a, Word8Array.length a) )
end
