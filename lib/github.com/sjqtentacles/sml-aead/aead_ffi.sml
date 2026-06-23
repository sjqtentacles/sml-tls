(* aead_ffi.sml

   FFI build variant of the AEAD facade (see aead.sml). Identical in shape and
   signature (`structure Aead :> AEAD`) to the pure-SML facade, but routes the
   primitive seal/open' to the OpenSSL/libsodium-backed CryptoFfi
   implementations, which are constant-time with respect to secret material:

     - AesGcm128 / AesGcm256  -> CryptoFfi.AesGcm        (OpenSSL libcrypto)
     - ChaCha20Poly1305       -> CryptoFfi.ChaCha20Poly1305 (libsodium)

   Because the signature is unchanged, every downstream consumer
   (recordprotect.sml, tlsstate.sml, ...) is recompiled against this variant
   verbatim. Only the dedicated FFI build (sources-ffi.mlb) selects this file
   in place of aead.sml; the default build stays 100% pure. *)

structure Aead :> AEAD =
struct
  datatype alg = ChaCha20Poly1305
               | AesGcm128
               | AesGcm256

  exception Aead of string

  val tagLen = 16

  fun keyLen ChaCha20Poly1305 = 32
    | keyLen AesGcm128         = 16
    | keyLen AesGcm256         = 32

  (* All three constructions take a 96-bit (12-byte) nonce / IV. *)
  fun nonceLen _ = 12

  fun checkLens alg {key, nonce} =
    let
      val kl = keyLen alg
      val nl = nonceLen alg
    in
      if String.size key <> kl then
        raise Aead ("key must be " ^ Int.toString kl ^ " bytes, got "
                    ^ Int.toString (String.size key))
      else if String.size nonce <> nl then
        raise Aead ("nonce must be " ^ Int.toString nl ^ " bytes, got "
                    ^ Int.toString (String.size nonce))
      else ()
    end

  (* The underlying CryptoFfi primitives share the curried shape
       seal  key nonce aad plaintext -> ciphertext||tag
       open' key nonce aad sealed     -> plaintext option *)
  fun primSeal ChaCha20Poly1305 = CryptoFfi.ChaCha20Poly1305.seal
    | primSeal AesGcm128         = CryptoFfi.AesGcm.seal
    | primSeal AesGcm256         = CryptoFfi.AesGcm.seal

  fun primOpen ChaCha20Poly1305 = CryptoFfi.ChaCha20Poly1305.open'
    | primOpen AesGcm128         = CryptoFfi.AesGcm.open'
    | primOpen AesGcm256         = CryptoFfi.AesGcm.open'

  fun seal alg {key, nonce, aad, plaintext} =
    ( checkLens alg {key = key, nonce = nonce}
    ; primSeal alg key nonce aad plaintext )

  fun open' alg {key, nonce, aad, ciphertext} =
    ( checkLens alg {key = key, nonce = nonce}
    ; primOpen alg key nonce aad ciphertext )

  structure Poly1305 =
  struct
    val mac    = Poly1305.mac
    val macHex = Poly1305.macHex
  end
end
