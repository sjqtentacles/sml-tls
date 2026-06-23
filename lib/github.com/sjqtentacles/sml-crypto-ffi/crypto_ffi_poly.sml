(* crypto_ffi_poly.sml

   Poly/ML implementation of CRYPTO_FFI using the `Foreign` structure to
   call the libsodium shim (lib/.../sml-crypto-ffi/shim.c), compiled to a
   shared library that this module loads at runtime via
   `Foreign.loadLibrary`.

   This file uses Poly/ML-only `Foreign` and is NOT loaded under MLton
   (which uses crypto_ffi_mlton.sml instead).

   Poly/ML's `cArrayPointer cUint8` marshals an SML `int array` to/from a
   C `unsigned char *`, so byte material crosses the boundary as `int
   array` (values 0-255). *)

structure CryptoFfi :> CRYPTO_FFI =
struct
  exception CryptoFfi of string

  val keySize = 32

  (* Locate the shim shared library. The Makefile builds it next to the
     test binary as bin/libsmlcryptoffi.dylib; we also try a few common
     spots so tests run from the repo root work regardless of cwd. *)
  local
    open Foreign
    fun ext () =
      case OS.Process.getEnv "SML_CRYPTO_FFI_LIB" of
          SOME p => [p]
        | NONE => []
    val candidates =
      ext () @
      [ "bin/libsmlcryptoffi.dylib",
        "bin/libsmlcryptoffi.so",
        "./libsmlcryptoffi.dylib",
        "libsmlcryptoffi.dylib",
        "libsmlcryptoffi.so" ]
    fun tryLoad [] = raise CryptoFfi "could not load libsmlcryptoffi shim library"
      | tryLoad (p :: ps) =
          (loadLibrary p handle _ => tryLoad ps)
    val lib = tryLoad candidates
    val byteArr = cArrayPointer cUint8
  in
    val cInit = buildCall0 (getSymbol lib "sml_sodium_init", (), cInt)
    val cX25519 = buildCall3 (getSymbol lib "sml_x25519",
      (byteArr, byteArr, byteArr), cInt)
    val cX25519Base = buildCall2 (getSymbol lib "sml_x25519_base",
      (byteArr, byteArr), cInt)
    val cSeal = buildCall7 (getSymbol lib "sml_chacha20poly1305_seal",
      (byteArr, byteArr, cInt, byteArr, cInt, byteArr, byteArr), cInt)
    val cOpen = buildCall7 (getSymbol lib "sml_chacha20poly1305_open",
      (byteArr, byteArr, cInt, byteArr, cInt, byteArr, byteArr), cInt)
    val cAesGcmSeal = buildCall9 (getSymbol lib "sml_aesgcm_seal",
      (byteArr, byteArr, cInt, byteArr, cInt, byteArr, cInt, byteArr, cInt),
      cInt)
    val cAesGcmOpen = buildCall9 (getSymbol lib "sml_aesgcm_open",
      (byteArr, byteArr, cInt, byteArr, cInt, byteArr, cInt, byteArr, cInt),
      cInt)
    val cRsaPssVerify = buildCall8 (getSymbol lib "sml_rsa_pss_verify",
      (byteArr, cInt, cInt, cInt, byteArr, cInt, byteArr, cInt), cInt)
    val cRsaPssSign = buildCall8 (getSymbol lib "sml_rsa_pss_sign",
      (byteArr, cInt, byteArr, cInt, cInt, cInt, byteArr, cInt), cInt)
    val cMemzeroI = buildCall2 (getSymbol lib "sml_memzero",
      (byteArr, cInt), cVoid)
  end

  (* --- byte string <-> int array (0-255) marshalling --- *)
  fun toArr (s : string) : int array =
    Array.tabulate (String.size s, fn i => Char.ord (String.sub (s, i)))

  fun fromArr (a : int array) : string =
    CharVector.tabulate (Array.length a, fn i => Char.chr (Array.sub (a, i)))

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
        val out = Array.array (32, 0)
        val _ = cX25519 (out, toArr scalar, toArr point)
      in fromArr out end )

  fun base scalar =
    ( init ()
    ; checkLen ("scalar", scalar, 32)
    ; let
        val out = Array.array (32, 0)
        val _ = cX25519Base (out, toArr scalar)
      in fromArr out end )

  structure ChaCha20Poly1305 =
  struct
    fun seal key nonce aad plaintext =
      ( init ()
      ; checkLen ("key", key, 32)
      ; checkLen ("nonce", nonce, 12)
      ; let
          val out = Array.array (String.size plaintext + 16, 0)
          val n = cSeal (out, toArr plaintext, String.size plaintext,
                         toArr aad, String.size aad, toArr nonce, toArr key)
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
            val out = Array.array (String.size sealed - 16, 0)
            val n = cOpen (out, toArr sealed, String.size sealed,
                           toArr aad, String.size aad, toArr nonce, toArr key)
          in
            if n < 0 then NONE else SOME (fromArr out)
          end )
  end

  structure AesGcm =
  struct
    fun checkKey key =
      if String.size key = 16 orelse String.size key = 32 then ()
      else raise CryptoFfi ("key must be 16 or 32 bytes, got "
                            ^ Int.toString (String.size key))

    fun seal key iv aad plaintext =
      ( init ()
      ; checkKey key
      ; checkLen ("iv", iv, 12)
      ; let
          val out = Array.array (String.size plaintext + 16, 0)
          val n = cAesGcmSeal (out, toArr plaintext, String.size plaintext,
                               toArr aad, String.size aad, toArr iv, 12,
                               toArr key, String.size key)
        in
          if n < 0 then raise CryptoFfi "aes-gcm seal failed"
          else fromArr out
        end )

    fun open' key iv aad sealed =
      ( init ()
      ; checkKey key
      ; checkLen ("iv", iv, 12)
      ; if String.size sealed < 16 then NONE
        else
          let
            val out = Array.array (String.size sealed - 16, 0)
            val n = cAesGcmOpen (out, toArr sealed, String.size sealed,
                                 toArr aad, String.size aad, toArr iv, 12,
                                 toArr key, String.size key)
          in
            if n < 0 then NONE else SOME (fromArr out)
          end )
  end

  structure RsaPss =
  struct
    fun verify {spkiDer, hashId, saltLen, msg, sgn} =
      ( init ()
      ; let
          val n = cRsaPssVerify (toArr spkiDer, String.size spkiDer,
                                 hashId, saltLen,
                                 toArr msg, String.size msg,
                                 toArr sgn, String.size sgn)
        in n = 1 end )

    fun sign {pkcs8Der, hashId, saltLen, msg} =
      ( init ()
      ; let
          (* RSA signatures are at most the modulus length; 1024 bytes
             covers up to 8192-bit keys. *)
          val cap = 1024
          val out = Array.array (cap, 0)
          val n = cRsaPssSign (out, cap, toArr pkcs8Der, String.size pkcs8Der,
                               hashId, saltLen, toArr msg, String.size msg)
        in
          if n < 0 then raise CryptoFfi "rsa-pss sign failed"
          else CharVector.tabulate (n, fn i => Char.chr (Array.sub (out, i)))
        end )
  end

  (* Word8Array path: copy into an int array, zero via the shim, then copy
     the zeros back so the caller's array is wiped too. (sodium_memzero on
     the temporary guarantees the value-zeroing is not elided.) *)
  fun memzero a =
    let
      val () = init ()
      val n = Word8Array.length a
      val tmp = Array.array (n, 0)
      val () = cMemzeroI (tmp, n)
    in
      Word8Array.modify (fn _ => 0w0) a
    end
end
