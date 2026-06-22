(* aead.sml -- CakeML port of sml-aead (RFC 8439 ChaCha20-Poly1305 and
   NIST AES-GCM) plus the algorithm-agnostic AEAD facade.

   The facade dispatches to the vendored primitives; since the CakeML tower
   has no shared linker, the primitives needed by the facade are inlined
   here in dependency order:
     ChaCha20 (RFC 8439 stream cipher, from cakeml/chacha20.sml)
     Poly1305 (RFC 8439 one-time MAC, native-int bignum field arithmetic)
     ChaCha20Poly1305 (RFC 8439 AEAD)
     AesBlock (FIPS 197 block cipher, from cakeml/aes.sml) + AesCtr + AesGcm
     Aead (the facade)

   Records are replaced by tuples (CakeML lacks records).  See
   aead_PORT_NOTES.md for the full dialect-gap list. *)

(* shared native-int power of two (Poly1305 / GCM length encodings) *)
fun pow2 n = if n <= 0 then 1 else 2 * pow2 (n - 1)

(* ================================================================== *)
(* ChaCha20 (Word32 emulated via Word64 + mask, per chacha20.sml)      *)
(* ================================================================== *)

structure ChaCha20 = struct

  val mask32 : Word64.word = 0wxFFFFFFFF
  fun add32 a b = Word64.andb (Word64.+ a b) mask32
  fun andb a b = Word64.andb a b
  fun orb  a b = Word64.orb a b
  fun xorb a b = Word64.xorb a b
  fun lsl32 a b = Word64.andb (Word64.<< a b) mask32
  fun lsr  a b = Word64.>> a b

  fun rotl32 x n = orb (lsl32 x n) (lsr x (32 - n))

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

  fun encrypt key nonce msg = xorStream key nonce msg 0w1
  fun decrypt key nonce ct  = xorStream key nonce ct  0w1
end

(* ================================================================== *)
(* Poly1305 one-time MAC (RFC 8439 2.5) -- native int field math       *)
(* ================================================================== *)

structure Poly1305 = struct
  val p = pow2 130 - 5

  fun byteAt s i = Char.ord (String.sub s i)

  fun leInt s off len =
    let
      fun loop (i, acc, mul) =
        if i >= len then acc
        else loop (i + 1, acc + byteAt s (off + i) * mul, mul * 256)
    in loop (0, 0, 1) end

  (* clamp r per RFC 8439: bytes 3,7,11,15 &= 15; bytes 4,8,12 &= 252 *)
  fun clampR key =
    let
      fun b i =
        let val v = byteAt key i
        in
          if i = 3 orelse i = 7 orelse i = 11 orelse i = 15 then v mod 16
          else if i = 4 orelse i = 8 orelse i = 12 then v - (v mod 4)
          else v
        end
      fun loop (i, acc, mul) =
        if i >= 16 then acc else loop (i + 1, acc + b i * mul, mul * 256)
    in loop (0, 0, 1) end

  fun mac key msg =
    let
      val r = clampR key
      val s = leInt key 16 16
      val mlen = String.size msg
      val nblk = (mlen + 15) div 16
      fun chunkN b =
        let val cl = if mlen - b*16 < 16 then mlen - b*16 else 16
        in leInt msg (b*16) cl + pow2 (8 * cl) end
      fun loop (b, acc) =
        if b >= nblk then acc
        else loop (b + 1, ((acc + chunkN b) * r) mod p)
      val acc = loop (0, 0)
      val tag = (acc + s) mod pow2 128
      fun getByte i = (tag div pow2 (8 * i)) mod 256
    in
      String.implode (List.tabulate 16 (fn i => Char.chr (getByte i)))
    end
end

(* ================================================================== *)
(* ChaCha20-Poly1305 AEAD (RFC 8439 2.8)                               *)
(* ================================================================== *)

structure ChaCha20Poly1305 = struct
  fun pad16 n =
    String.implode (List.tabulate ((16 - n mod 16) mod 16) (fn _ => #"\000"))

  fun le64 n =
    String.implode (List.tabulate 8 (fn i => Char.chr ((n div pow2 (8 * i)) mod 256)))

  fun polyKey key nonce =
    String.substring (ChaCha20.block key nonce (Word64.fromInt 0)) 0 32

  fun authMsg aad ct =
    aad ^ pad16 (String.size aad) ^
    ct  ^ pad16 (String.size ct)  ^
    le64 (String.size aad) ^ le64 (String.size ct)

  fun seal key nonce aad msg =
    let
      val ct  = ChaCha20.encrypt key nonce msg
      val tag = Poly1305.mac (polyKey key nonce) (authMsg aad ct)
    in ct ^ tag end

  fun open' key nonce aad sealed =
    let val slen = String.size sealed
    in if slen < 16 then None
       else
         let
           val ct       = String.substring sealed 0 (slen - 16)
           val tag      = String.substring sealed (slen - 16) 16
           val expected = Poly1305.mac (polyKey key nonce) (authMsg aad ct)
         in
           if String.= expected tag
           then Some (ChaCha20.decrypt key nonce ct)
           else None
         end
    end
end

(* ================================================================== *)
(* AES block cipher (FIPS 197, per aes.sml)                            *)
(* ================================================================== *)

structure AesBlock = struct

  val sboxV : Word8.word Array.array = Array.fromList (List.map Word8.fromInt
    [ 99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118
    ,202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192
    ,183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21
    ,  4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117
    ,  9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132
    , 83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207
    ,208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168
    , 81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210
    ,205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115
    , 96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219
    ,224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121
    ,231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8
    ,186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138
    ,112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158
    ,225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223
    ,140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22 ])

  val rc : Word8.word Array.array = Array.fromList (List.map Word8.fromInt
    [1,2,4,8,16,32,64,128,27,54])

  val mask32 : Word64.word = 0wxFFFFFFFF
  fun add32 a b = Word64.andb (Word64.+ a b) mask32
  fun andb a b = Word64.andb a b
  fun orb  a b = Word64.orb a b
  fun xorb a b = Word64.xorb a b
  fun lsl32 a b = Word64.andb (Word64.<< a b) mask32
  fun lsr  a b = Word64.>> a b

  fun xt b =
    let val s = Word8.<< b 1
    in
      if not (Word8.= (Word8.andb b (Word8.fromInt 0x80)) (Word8.fromInt 0))
      then Word8.xorb s (Word8.fromInt 0x1b)
      else s
    end

  fun gm a b =
    let
      fun go n a b acc =
        if n <= 0 then acc
        else
          let val acc2 = if not (Word8.= (Word8.andb b (Word8.fromInt 1)) (Word8.fromInt 0)) then Word8.xorb acc a else acc
          in go (n-1) (xt a) (Word8.>> b 1) acc2 end
    in go 8 a b (Word8.fromInt 0) end

  fun subW w =
    let fun s n =
      let val byte = Word64.toInt (andb (lsr w n) 0wxFF)
          val sb = Word8.toInt (Array.sub sboxV byte)
      in Word64.fromInt sb end
    in
      orb (orb (orb (lsl32 (s 24) 24) (lsl32 (s 16) 16))
               (lsl32 (s 8) 8)) (s 0)
    end

  fun rotW w = orb (lsl32 w 8) (lsr w 24)

  fun getW32 s off =
    let val b0 = Word64.fromInt (Char.ord (String.sub s off))
        val b1 = Word64.fromInt (Char.ord (String.sub s (off+1)))
        val b2 = Word64.fromInt (Char.ord (String.sub s (off+2)))
        val b3 = Word64.fromInt (Char.ord (String.sub s (off+3)))
    in
      orb (orb (orb (lsl32 b0 24) (lsl32 b1 16)) (lsl32 b2 8)) b3
    end

  fun putW32 w =
    let fun b n = Char.chr (Word64.toInt (andb (lsr w n) 0wxFF))
    in String.implode [b 24, b 16, b 8, b 0] end

  fun xorBytes a b =
    String.implode (List.tabulate (String.size a)
      (fn i =>
        Char.chr (Word8.toInt (Word8.xorb
          (Word8.fromInt (Char.ord (String.sub a i)))
          (Word8.fromInt (Char.ord (String.sub b i)))))))

  fun keySize ((nr, _)) = (nr - 6) * 4

  fun expandKey keyBytes nk =
    let
      val nr = nk + 6
      val total = (nr + 1) * 4
      val w = Array.array total (0w0 : Word64.word)
      val () = List.app
        (fn i => Array.update w i (getW32 keyBytes (i*4)))
        (List.tabulate nk (fn i => i))
      val () = List.app
        (fn i =>
          let val prev = Array.sub w (i-1)
              val temp =
                if i mod nk = 0 then
                  xorb (subW (rotW prev))
                    (lsl32 (Word64.fromInt (Word8.toInt (Array.sub rc (i div nk - 1)))) 24)
                else if nk > 6 andalso i mod nk = 4 then subW prev
                else prev
          in Array.update w i (xorb (Array.sub w (i-nk)) temp) end)
        (List.tabulate (total - nk) (fn i => i + nk))
    in (nr, w) end

  fun expand128 k = expandKey k 4
  fun expand192 k = expandKey k 6
  fun expand256 k = expandKey k 8

  fun blockToState b =
    Array.tabulate 16 (fn i => Word8.fromInt (Char.ord (String.sub b i)))

  fun stateToBlock s =
    String.implode (List.tabulate 16 (fn i => Char.chr (Word8.toInt (Array.sub s i))))

  fun addRK st w round =
    List.app
      (fn c =>
        let val word = Array.sub w (round*4 + c)
            fun b n = Word8.fromInt (Word64.toInt (andb (lsr word n) 0wxFF))
        in
          ( Array.update st (c*4+0) (Word8.xorb (Array.sub st (c*4+0)) (b 24))
          ; Array.update st (c*4+1) (Word8.xorb (Array.sub st (c*4+1)) (b 16))
          ; Array.update st (c*4+2) (Word8.xorb (Array.sub st (c*4+2)) (b 8))
          ; Array.update st (c*4+3) (Word8.xorb (Array.sub st (c*4+3)) (b 0)) )
        end)
      [0,1,2,3]

  fun subB st =
    List.app
      (fn i => Array.update st i (Array.sub sboxV (Word8.toInt (Array.sub st i))))
      (List.tabulate 16 (fn i => i))

  fun getRow st r = List.tabulate 4 (fn c => Array.sub st (c*4 + r))

  fun setRow st r xs =
    List.app
      (fn (c, v) => Array.update st (c*4 + r) v)
      (List.zip ([0,1,2,3], xs))

  fun shiftR st =
    let
      val r1 = getRow st 1
      val r2 = getRow st 2
      val r3 = getRow st 3
    in
      ( setRow st 1 [List.nth r1 1, List.nth r1 2, List.nth r1 3, List.nth r1 0]
      ; setRow st 2 [List.nth r2 2, List.nth r2 3, List.nth r2 0, List.nth r2 1]
      ; setRow st 3 [List.nth r3 3, List.nth r3 0, List.nth r3 1, List.nth r3 2] )
    end

  fun mixC st c =
    let val off = c*4
        val s0 = Array.sub st off
        val s1 = Array.sub st (off+1)
        val s2 = Array.sub st (off+2)
        val s3 = Array.sub st (off+3)
    in
      ( Array.update st off
          (Word8.xorb (Word8.xorb (Word8.xorb (gm (Word8.fromInt 2) s0) (gm (Word8.fromInt 3) s1)) s2) s3)
      ; Array.update st (off+1)
          (Word8.xorb (Word8.xorb (Word8.xorb s0 (gm (Word8.fromInt 2) s1)) (gm (Word8.fromInt 3) s2)) s3)
      ; Array.update st (off+2)
          (Word8.xorb (Word8.xorb (Word8.xorb s0 s1) (gm (Word8.fromInt 2) s2)) (gm (Word8.fromInt 3) s3))
      ; Array.update st (off+3)
          (Word8.xorb (Word8.xorb (Word8.xorb (gm (Word8.fromInt 3) s0) s1) s2) (gm (Word8.fromInt 2) s3)) )
    end

  fun encrypt ((nr, w)) blk =
    let
      val st = blockToState blk
      val () = addRK st w 0
      fun round r =
        if r > nr then ()
        else
          ( subB st
          ; shiftR st
          ; if r < nr then List.app (mixC st) [0,1,2,3] else ()
          ; addRK st w r
          ; round (r + 1) )
      val () = round 1
    in stateToBlock st end

  fun selectKey keyBytes =
    if String.size keyBytes = 16 then expand128 keyBytes
    else if String.size keyBytes = 24 then expand192 keyBytes
    else expand256 keyBytes
end

(* ================================================================== *)
(* AES-CTR (counter mode keystream)                                    *)
(* ================================================================== *)

structure AesCtr = struct
  fun incCtr ctr =
    let
      val bytes = Array.tabulate 16 (fn i => Char.ord (String.sub ctr i))
      fun inc i =
        if i < 0 then ()
        else let val v = (Array.sub bytes i + 1) mod 256
             in (Array.update bytes i v; if v = 0 then inc (i-1) else ()) end
    in
      (inc 15; String.implode (List.tabulate 16 (fn i => Char.chr (Array.sub bytes i))))
    end

  fun xorStream keyBytes iv data =
    let val key = AesBlock.selectKey keyBytes
        val n    = String.size data
        val nblk = (n + 15) div 16
        val buf  = Array.array n #"\000"
        val ctr  = Ref iv
        val ()   = List.app (fn b =>
            let val ks = AesBlock.encrypt key (!ctr)
                val _  = ctr := incCtr (!ctr)
                val sz = if n - b*16 < 16 then n - b*16 else 16
            in List.app (fn i =>
                 Array.update buf (b*16+i)
                   (Char.chr (Word8.toInt (Word8.xorb
                     (Word8.fromInt (Char.ord (String.sub data (b*16+i))))
                     (Word8.fromInt (Char.ord (String.sub ks i)))))))
               (List.tabulate sz (fn i => i))
            end)
          (List.tabulate nblk (fn i => i))
    in String.implode (Array.foldr (fn x => fn xs => x :: xs) [] buf) end

  fun encrypt k iv pt = xorStream k iv pt
  fun decrypt k iv ct = xorStream k iv ct
end

(* ================================================================== *)
(* AES-GCM AEAD (NIST)                                                 *)
(* ================================================================== *)

structure AesGcm = struct
  val w0 = Word8.fromInt 0
  val w1 = Word8.fromInt 1

  fun isSet w = not (Word8.= w w0)

  (* GHASH GF(2^128) multiply; reduction polynomial x^128+x^7+x^2+x+1 *)
  fun ghashMul x y =
    let
      val z = Array.array 16 w0
      val v = Array.tabulate 16 (fn i => Word8.fromInt (Char.ord (String.sub y i)))
      val () = List.app (fn i =>
          List.app (fn j =>
            let
              val bit = isSet (Word8.andb (Word8.>> (Word8.fromInt (Char.ord (String.sub x i)) ) (7 - j)) w1)
            in
              ( if bit then
                  List.app (fn k => Array.update z k (Word8.xorb (Array.sub z k) (Array.sub v k)))
                    (List.tabulate 16 (fn k => k))
                else ()
              ; let val outBit = isSet (Word8.andb (Array.sub v 15) w1)
                in
                  ( List.app (fn k =>
                      Array.update v k
                        (Word8.orb
                          (Word8.>> (Array.sub v k) 1)
                          (if k > 0 then Word8.<< (Word8.andb (Array.sub v (k-1)) w1) 7 else w0)))
                      (List.rev (List.tabulate 16 (fn k => k)))
                  ; if outBit then Array.update v 0 (Word8.xorb (Array.sub v 0) (Word8.fromInt 0xe1))
                    else () )
                end )
            end)
            (List.tabulate 8 (fn j => j)))
        (List.tabulate 16 (fn i => i))
    in
      String.implode (List.tabulate 16 (fn i => Char.chr (Word8.toInt (Array.sub z i))))
    end

  fun ghash h aad ct =
    let
      fun padTo16 s =
        let val n = String.size s
            val pad = (16 - n mod 16) mod 16
        in s ^ String.implode (List.tabulate pad (fn _ => #"\000")) end

      fun be64 n =
        String.implode (List.tabulate 8 (fn i =>
          Char.chr ((n div pow2 (56 - i*8)) mod 256)))

      val data = padTo16 aad ^ padTo16 ct ^
                 be64 (String.size aad * 8) ^ be64 (String.size ct * 8)
      val nblk = String.size data div 16
    in
      List.foldl (fn i => fn y =>
        ghashMul (AesBlock.xorBytes y (String.substring data (i*16) 16)) h)
      (String.implode (List.tabulate 16 (fn _ => #"\000")))
      (List.tabulate nblk (fn i => i))
    end

  fun incCtr32 ctr =
    let
      val bytes = Array.tabulate 16 (fn i => Char.ord (String.sub ctr i))
      fun inc i =
        if i < 12 then ()
        else let val v = (Array.sub bytes i + 1) mod 256
             in (Array.update bytes i v; if v = 0 then inc (i-1) else ()) end
    in
      (inc 15; String.implode (List.tabulate 16 (fn i => Char.chr (Array.sub bytes i))))
    end

  val zeros16 = String.implode (List.tabulate 16 (fn _ => #"\000"))

  fun seal keyBytes iv aad pt =
    let val key   = AesBlock.selectKey keyBytes
        val h     = AesBlock.encrypt key zeros16
        val j0    = iv ^ "\000\000\000\001"
        val ct    = AesCtr.encrypt keyBytes (incCtr32 j0) pt
        val tag0  = AesBlock.encrypt key j0
        val s     = ghash h aad ct
        val tag   = AesBlock.xorBytes s tag0
    in ct ^ tag end

  fun open' keyBytes iv aad sealed =
    let val slen = String.size sealed
    in if slen < 16 then None
       else let
         val ct  = String.substring sealed 0 (slen - 16)
         val tag = String.substring sealed (slen - 16) 16
         val key = AesBlock.selectKey keyBytes
         val h    = AesBlock.encrypt key zeros16
         val j0   = iv ^ "\000\000\000\001"
         val s    = ghash h aad ct
         val expected = AesBlock.xorBytes s (AesBlock.encrypt key j0)
       in if String.= expected tag then Some (AesCtr.decrypt keyBytes (incCtr32 j0) ct)
          else None
       end
    end
end

(* ================================================================== *)
(* AEAD facade                                                         *)
(* ================================================================== *)

structure Aead = struct
  datatype alg = AChaCha20Poly1305 | AAesGcm128 | AAesGcm256

  exception Aead string

  val tagLen = 16

  fun keyLen a =
    case a of AChaCha20Poly1305 => 32 | AAesGcm128 => 16 | AAesGcm256 => 32

  fun nonceLen _ = 12

  fun checkLens alg key nonce =
    if String.size key <> keyLen alg then raise Aead "bad key length"
    else if String.size nonce <> nonceLen alg then raise Aead "bad nonce length"
    else ()

  (* (key, nonce, aad, plaintext) -> ciphertext || tag *)
  fun seal alg (key, nonce, aad, plaintext) =
    ( checkLens alg key nonce
    ; case alg of
          AChaCha20Poly1305 => ChaCha20Poly1305.seal key nonce aad plaintext
        | _ => AesGcm.seal key nonce aad plaintext )

  (* (key, nonce, aad, ciphertext||tag) -> plaintext option *)
  fun open' alg (key, nonce, aad, ciphertext) =
    ( checkLens alg key nonce
    ; case alg of
          AChaCha20Poly1305 => ChaCha20Poly1305.open' key nonce aad ciphertext
        | _ => AesGcm.open' key nonce aad ciphertext )
end
