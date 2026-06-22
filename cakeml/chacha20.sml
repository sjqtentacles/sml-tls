(* chacha20.sml -- CakeML port of sml-chacha20 (RFC 8439).

   Only the ChaCha20 stream cipher (block function + encrypt/decrypt) is
   ported here, per the L0 scope.  Poly1305 and the AEAD construction are
   left for a later layer; they need CakeML `int` bignum arithmetic and
   would expand the surface beyond the L0 gate.

   Dialect-gap fixes applied (see SPIKE_REPORT.md):
     - Word32 emulated via Word64 + 0wxFFFFFFFF mask (add32/rotl32/etc.)
     - `ref`/`!`/`:=` work, but the Ref constructor is `Ref` (not `ref`)
     - `True`/`False` instead of `true`/`false`
     - multi-clause `fun` rewritten as `if`/`case`
     - curried `fn x y => ...` rewritten as `fn x => fn y => ...`
     - no signatures / `:> SIG`
*)

structure ChaCha20 = struct

  val mask32 : Word64.word = 0wxFFFFFFFF

  fun add32 a b = Word64.andb (Word64.+ a b) mask32
  fun andb a b = Word64.andb a b
  fun orb  a b = Word64.orb a b
  fun xorb a b = Word64.xorb a b
  fun lsl32 a b = Word64.andb (Word64.<< a b) mask32
  fun lsr  a b = Word64.>> a b

  (* rotate left within the 32-bit window *)
  fun rotl32 x n =
    orb (lsl32 x n) (lsr x (32 - n))

  fun getLE32 s off =
    let val b0 = Word64.fromInt (Char.ord (String.sub s off))
        val b1 = Word64.fromInt (Char.ord (String.sub s (off+1)))
        val b2 = Word64.fromInt (Char.ord (String.sub s (off+2)))
        val b3 = Word64.fromInt (Char.ord (String.sub s (off+3)))
    in
      orb (orb (orb b0 (lsl32 b1 8)) (lsl32 b2 16)) (lsl32 b3 24)
    end

  fun putLE32 w =
    let fun b n = Char.chr (Word64.toInt (andb (lsr w (n*8)) 0wxFF))
    in String.implode [b 0, b 1, b 2, b 3] end

  val sigma0 = 0wx61707865 : Word64.word
  val sigma1 = 0wx3320646e : Word64.word
  val sigma2 = 0wx79622d32 : Word64.word
  val sigma3 = 0wx6b206574 : Word64.word

  (* one quarter round; refs hold the 4 state words *)
  fun qr sa sb sc sd =
    ( sa := add32 (!sa) (!sb)
    ; sd := rotl32 (xorb (!sd) (!sa)) 16
    ; sc := add32 (!sc) (!sd)
    ; sb := rotl32 (xorb (!sb) (!sc)) 12
    ; sa := add32 (!sa) (!sb)
    ; sd := rotl32 (xorb (!sd) (!sa)) 8
    ; sc := add32 (!sc) (!sd)
    ; sb := rotl32 (xorb (!sb) (!sc)) 7 )

  fun block key nonce counter =
    let
      val init = Array.fromList
        [ sigma0, sigma1, sigma2, sigma3
        , getLE32 key 0,  getLE32 key 4,  getLE32 key 8,  getLE32 key 12
        , getLE32 key 16, getLE32 key 20, getLE32 key 24, getLE32 key 28
        , counter
        , getLE32 nonce 0, getLE32 nonce 4, getLE32 nonce 8 ]
      val st = Array.tabulate 16 (fn i => Ref (Array.sub init i))
      fun s i = Array.sub st i

      fun doubleRound () =
        ( qr (s 0) (s 4) (s 8)  (s 12)
        ; qr (s 1) (s 5) (s 9)  (s 13)
        ; qr (s 2) (s 6) (s 10) (s 14)
        ; qr (s 3) (s 7) (s 11) (s 15)
        ; qr (s 0) (s 5) (s 10) (s 15)
        ; qr (s 1) (s 6) (s 11) (s 12)
        ; qr (s 2) (s 7) (s 8)  (s 13)
        ; qr (s 3) (s 4) (s 9)  (s 14) )

      fun doRounds n = if n <= 0 then () else (doubleRound (); doRounds (n - 1))
      val () = doRounds 10

      val out = Array.tabulate 16 (fn i => add32 (! (s i)) (Array.sub init i))
    in
      String.concat (List.tabulate 16 (fn i => putLE32 (Array.sub out i)))
    end

  fun xorStream key nonce msg startCtr =
    let
      val mlen = String.size msg
      val buf = Array.array mlen #"\000"
      val nblk = mlen div 64
      val rem = mlen mod 64

      fun fullBlock b =
        let val ks = block key nonce (add32 startCtr (Word64.fromInt b))
        in
          List.app
            (fn i =>
              let val off = b*64 + i
                  val mb = Word8.fromInt (Char.ord (String.sub msg off))
                  val kb = Word8.fromInt (Char.ord (String.sub ks i))
              in Array.update buf off (Char.chr (Word8.toInt (Word8.xorb mb kb))) end)
            (List.tabulate 64 (fn i => i))
        end
      val () = List.app fullBlock (List.tabulate nblk (fn i => i))

      fun tail () =
        if rem > 0 then
          let val ks = block key nonce (add32 startCtr (Word64.fromInt nblk))
              val off0 = nblk * 64
          in
            List.app
              (fn i =>
                let val mb = Word8.fromInt (Char.ord (String.sub msg (off0 + i)))
                    val kb = Word8.fromInt (Char.ord (String.sub ks i))
                in Array.update buf (off0 + i)
                     (Char.chr (Word8.toInt (Word8.xorb mb kb))) end)
              (List.tabulate rem (fn i => i))
          end
        else ()
      val () = tail ()
    in
      String.implode (Array.foldr (fn x => fn xs => x :: xs) [] buf)
    end

  (* Message encryption begins at counter = 1; counter 0 reserved for Poly1305 key *)
  fun encrypt key nonce msg = xorStream key nonce msg 0w1
  fun decrypt key nonce ct  = xorStream key nonce ct  0w1

  (* ----- hex helpers for the test harness ----- *)
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

  fun bytesToHex s = toHex s

end
