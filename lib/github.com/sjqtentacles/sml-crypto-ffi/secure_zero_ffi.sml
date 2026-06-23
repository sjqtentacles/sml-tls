(* secure_zero_ffi.sml

   FFI-backed implementation of SECURE_ZERO: delegates to CryptoFfi.memzero,
   which calls libsodium's sodium_memzero -- a wipe the C optimizer is
   guaranteed not to elide. Used by the FFI build targets, which also link
   the shim and load the CryptoFfi structure (MLton _import / Poly/ML
   Foreign). The default build uses secure_zero_pure.sml instead. *)

structure SecureZero :> SECURE_ZERO =
struct
  val ffiBacked = true

  fun zero a = CryptoFfi.memzero a

  fun zeroString s =
    let
      val n = String.size s
      val a = Word8Array.tabulate (n, fn i => Byte.charToByte (String.sub (s, i)))
      val () = zero a
    in
      CharVector.tabulate (n, fn i => Byte.byteToChar (Word8Array.sub (a, i)))
    end
end
