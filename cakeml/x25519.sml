(* x25519.sml -- CakeML port of sml-x25519 (RFC 7748).

   Curve25519 Diffie-Hellman key exchange.  The original uses IntInf for
   field arithmetic; CakeML's `int` is already arbitrary precision, so
   IntInf maps to int.  The IntInf bitwise operations (andb, ~>>) are
   replaced with div/mod arithmetic since CakeML int has no bitwise ops.

   Dialect-gap fixes (see SPIKE_REPORT.md, chacha20_PORT_NOTES.md,
   aes_PORT_NOTES.md):
     - IntInf -> int (CakeML int is bignum)
     - IntInf.<< / ~>> -> div / mod by powers of 2
     - IntInf.andb (e, 1) -> e mod 2
     - IntInf.orb/xorb on big ints -> not needed (only byte-level, use Word8)
     - CharVector.tabulate -> String.implode o List.tabulate
     - raise Fail -> works (exception FailMsg)
     - true/false -> True/False; SOME/NONE -> Some/None
     - char comparisons use Char.>=/Char.<=
     - no signatures / :> SIG
*)

structure X25519 = struct

  val keySize = 32

  exception FailMsg string

  (* ----- byte string <-> int helpers ----- *)

  fun byteAt (s, i) = Char.ord (String.sub s i)

  fun require32 s =
    if String.size s <> keySize
    then raise FailMsg "X25519: expected 32 bytes"
    else ()

  (* little-endian decode of a 32-byte string into an int *)
  fun leDecode s =
    let
      fun loop (i, acc) =
        if i < 0 then acc
        else loop (i - 1, acc * 256 + byteAt (s, i))
    in
      loop (keySize - 1, 0)
    end

  (* 2^n via repeated doubling *)
  fun pow2 n = if n <= 0 then 1 else 2 * pow2 (n - 1)

  (* little-endian encode an int into a 32-byte string *)
  fun leEncode n =
    let
      fun byte i = Char.chr ((n div pow2 (8 * i)) mod 256)
    in
      String.implode (List.tabulate keySize byte)
    end

  (* ----- scalar clamping (RFC 7748 section 5) ----- *)

  fun clamp s =
    let
      val () = require32 s
      fun mapByte i =
        let val b = Char.ord (String.sub s i)
        in
          if i = 0 then Char.chr (Word8.toInt (Word8.andb (Word8.fromInt b) (Word8.fromInt 0xF8)))
          else if i = 31 then
            Char.chr (Word8.toInt (Word8.orb (Word8.andb (Word8.fromInt b) (Word8.fromInt 0x7F)) (Word8.fromInt 0x40)))
          else Char.chr b
        end
    in
      String.implode (List.tabulate keySize mapByte)
    end

  (* ----- field arithmetic mod p = 2^255 - 19 ----- *)

  val p = pow2 255 - 19

  fun fadd (a, b) = (a + b) mod p
  fun fsub (a, b) = ((a - b) mod p + p) mod p
  fun fmul (a, b) = (a * b) mod p

  (* modular exponentiation via square-and-multiply *)
  fun fpow (base, e) =
    let
      fun loop (b, e, acc) =
        if e = 0 then acc
        else
          let val acc2 = if e mod 2 = 1 then fmul (acc, b) else acc
          in loop (fmul (b, b), e div 2, acc2) end
    in
      loop (base mod p, e, 1)
    end

  fun finv a = fpow (a, p - 2)

  (* decodeUCoordinate: mask the high (255th) bit of the last byte (RFC 7748). *)
  fun decodeUCoordinate s =
    let
      val () = require32 s
      fun byte i =
        if i = 31
        then Char.chr (Word8.toInt (Word8.andb (Word8.fromInt (Char.ord (String.sub s 31))) (Word8.fromInt 0x7F)))
        else String.sub s i
      val masked = String.implode (List.tabulate keySize byte)
    in
      leDecode masked mod p
    end

  (* a24 = (486662 - 2) / 4 *)
  val a24 = 121665

  (* Conditional swap used by the Montgomery ladder. *)
  fun cswap (swap, a, b) = if swap = 1 then (b, a) else (a, b)

  (* X25519 scalar multiplication (RFC 7748 Montgomery ladder). *)
  fun scalarMult (scalarStr, uStr) =
    let
      val () = require32 scalarStr
      val () = require32 uStr
      val k = leDecode (clamp scalarStr)
      val x1 = decodeUCoordinate uStr
      fun loop (t, x2, z2, x3, z3, swapPrev) =
        if t < 0 then (x2, z2, swapPrev, x3, z3)
        else
          let
            val kt = (k div pow2 t) mod 2
            val swap = if kt = swapPrev then 0 else 1
            val (x2b, x3b) = cswap (swap, x2, x3)
            val (z2b, z3b) = cswap (swap, z2, z3)
            val swapPrev = kt

            val a = fadd (x2b, z2b)
            val aa = fmul (a, a)
            val b = fsub (x2b, z2b)
            val bb = fmul (b, b)
            val e = fsub (aa, bb)
            val c = fadd (x3b, z3b)
            val d = fsub (x3b, z3b)
            val da = fmul (d, a)
            val cb = fmul (c, b)
            val x3c = let val tt = fadd (da, cb) in fmul (tt, tt) end
            val z3c = let val tt = fsub (da, cb) in fmul (x1, fmul (tt, tt)) end
            val x2c = fmul (aa, bb)
            val z2c = fmul (e, fadd (aa, fmul (a24, e)))
          in
            loop (t - 1, x2c, z2c, x3c, z3c, swapPrev)
          end
      val (x2, z2, swapFinal, x3, z3) = loop (254, 1, 0, x1, 1, 0)
      val (x2f, _) = cswap (swapFinal, x2, x3)
      val (z2f, _) = cswap (swapFinal, z2, z3)
      val result = fmul (x2f, finv z2f)
    in
      leEncode result
    end

  fun dh scalarStr uStr = scalarMult (scalarStr, uStr)

  val basePoint =
    String.str (Char.chr 9) ^ String.implode (List.tabulate 31 (fn _ => Char.chr 0))

  fun base scalarStr = scalarMult (scalarStr, basePoint)

  (* ----- hex convenience ----- *)

  val hexChars = "0123456789abcdef"

  fun toHex s =
    String.concat
      (List.map
        (fn c =>
          let val v = Char.ord c
          in String.str (String.sub hexChars (v div 16)) ^
             String.str (String.sub hexChars (v mod 16))
          end)
        (String.explode s))

  fun hexVal (c : char) =
    if Char.>= c #"0" andalso Char.<= c #"9" then Some (Char.ord c - Char.ord #"0")
    else if Char.>= c #"a" andalso Char.<= c #"f" then Some (Char.ord c - Char.ord #"a" + 10)
    else if Char.>= c #"A" andalso Char.<= c #"F" then Some (Char.ord c - Char.ord #"A" + 10)
    else None

  fun fromHex s =
    let
      val n = String.size s
    in
      if n mod 2 <> 0 then None
      else
        let
          fun loop (i, acc) =
            if i >= n then Some (String.implode (List.rev acc))
            else
              case (hexVal (String.sub s i), hexVal (String.sub s (i + 1))) of
                  (Some hi, Some lo) => loop (i + 2, Char.chr (hi * 16 + lo) :: acc)
                | _ => None
        in
          loop (0, [])
        end
    end

end
