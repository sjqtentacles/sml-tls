(* secure_zero_pure.sml

   Portable (non-FFI) implementation of SECURE_ZERO, used by the default
   build where the libsodium shim is not linked. Uses Word8Array.modify,
   which both MLton and Poly/ML retain (the array is observable through
   the reference the caller still holds), giving a best-effort wipe. The
   FFI build (secure_zero_ffi.sml) upgrades this to sodium_memzero. *)

structure SecureZero :> SECURE_ZERO =
struct
  val ffiBacked = false

  fun zero a = Word8Array.modify (fn _ => 0w0) a

  fun zeroString s =
    let
      val n = String.size s
      val a = Word8Array.tabulate (n, fn i => Byte.charToByte (String.sub (s, i)))
      val () = zero a
    in
      CharVector.tabulate (n, fn i => Byte.byteToChar (Word8Array.sub (a, i)))
    end
end
