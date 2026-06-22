(* kdf.sml -- CakeML port of sml-kdf's HKDF (RFC 5869) over HMAC-SHA-256.

   HKDF is the L2 KDF in scope.  It is built on HMAC-SHA-256 (RFC 2104),
   which is built on SHA-256 (FIPS 180-4, reused from cakeml/sha256.sml);
   both are inlined here.  scrypt and the SHA-512 PRF path from the original
   sml-kdf are out of scope for this layer (scrypt's Salsa20/8 core and the
   SHA-512 primitive are not ported); `hkdf*` here is SHA-256-only.

   Records replaced by tuples.  See kdf_PORT_NOTES.md. *)

structure Sha256 = struct

  val mask32 : Word64.word = 0wxFFFFFFFF
  fun add32 a b = Word64.andb (Word64.+ a b) mask32
  fun andb a b = Word64.andb a b
  fun orb  a b = Word64.orb a b
  fun xorb a b = Word64.xorb a b
  fun lsl32 a b = Word64.andb (Word64.<< a b) mask32
  fun lsr a b = Word64.>> a b
  fun notb w = Word64.xorb w mask32

  fun rotr w n =
    Word64.orb (Word64.>> w n) (Word64.andb (Word64.<< w (32 - n)) mask32)

  val k : Word64.word Vector.vector = Vector.fromList
    [0wx428a2f98,0wx71374491,0wxb5c0fbcf,0wxe9b5dba5,0wx3956c25b,0wx59f111f1,
     0wx923f82a4,0wxab1c5ed5,0wxd807aa98,0wx12835b01,0wx243185be,0wx550c7dc3,
     0wx72be5d74,0wx80deb1fe,0wx9bdc06a7,0wxc19bf174,0wxe49b69c1,0wxefbe4786,
     0wx0fc19dc6,0wx240ca1cc,0wx2de92c6f,0wx4a7484aa,0wx5cb0a9dc,0wx76f988da,
     0wx983e5152,0wxa831c66d,0wxb00327c8,0wxbf597fc7,0wxc6e00bf3,0wxd5a79147,
     0wx06ca6351,0wx14292967,0wx27b70a85,0wx2e1b2138,0wx4d2c6dfc,0wx53380d13,
     0wx650a7354,0wx766a0abb,0wx81c2c92e,0wx92722c85,0wxa2bfe8a1,0wxa81a664b,
     0wxc24b8b70,0wxc76c51a3,0wxd192e819,0wxd6990624,0wxf40e3585,0wx106aa070,
     0wx19a4c116,0wx1e376c08,0wx2748774c,0wx34b0bcb5,0wx391c0cb3,0wx4ed8aa4a,
     0wx5b9cca4f,0wx682e6ff3,0wx748f82ee,0wx78a5636f,0wx84c87814,0wx8cc70208,
     0wx90befffa,0wxa4506ceb,0wxbef9a3f7,0wxc67178f2]

  fun shiftFactor i =
    if i = 0 then 1
    else if i = 1 then 256
    else if i = 2 then 65536
    else if i = 3 then 16777216
    else if i = 4 then 4294967296
    else if i = 5 then 1099511627776
    else if i = 6 then 281474976710656
    else 72057594037927936

  fun padded (msg : string) =
    let
      val len = String.size msg
      val bitLen = len * 8
      val withOne = msg ^ String.str (Char.chr 0x80)
      val padZeros : int =
        let val m = String.size withOne mod 64
        in if m <= 56 then 56 - m else 120 - m end
      val zeros = String.implode (List.tabulate padZeros (fn _ => Char.chr 0))
      fun lenByte i = Char.chr ((bitLen div shiftFactor i) mod 256)
      val lenBytes = String.implode (List.map lenByte [7,6,5,4,3,2,1,0])
      val full = withOne ^ zeros ^ lenBytes
      val n = String.size full
      fun word i =
        let fun b kk = Word64.fromInt (Char.ord (String.sub full (i + kk)))
        in Word64.orb
             (Word64.orb (Word64.<< (b 0) 24) (Word64.<< (b 1) 16))
             (Word64.orb (Word64.<< (b 2) 8) (b 3))
        end
      fun loop i acc = if i >= n then List.rev acc else loop (i + 4) (word i :: acc)
    in
      loop 0 []
    end

  fun chunk16 ws =
    case ws of
        [] => []
      | _ =>
          let
            fun take j xs acc =
              if j = 0 then (List.rev acc, xs)
              else case xs of
                     [] => (List.rev acc, [])
                   | (x :: rest) => take (j - 1) rest (x :: acc)
            val (blk, rest) = take 16 ws []
          in blk :: chunk16 rest end

  fun processBlock (st, block) =
    case st of
      (h0,h1,h2,h3,h4,h5,h6,h7) =>
    let
      val w = Array.array 64 (0w0 : Word64.word)
      fun fillBlock x i = (Array.update w i x; i + 1)
      val _ = List.foldl fillBlock 0 block
      fun extend i =
        if i >= 64 then ()
        else
          let
            val w15 = Array.sub w (i-15)
            val w2  = Array.sub w (i-2)
            val s0 = xorb (xorb (rotr w15 7) (rotr w15 18)) (lsr w15 3)
            val s1 = xorb (xorb (rotr w2 17) (rotr w2 19)) (lsr w2 10)
          in
            Array.update w i
              (add32 (add32 (add32 (Array.sub w (i-16)) s0) (Array.sub w (i-7))) s1);
            extend (i + 1)
          end
      val () = extend 16

      fun round (i, a, b, c, d, e, f, g, h) =
        if i >= 64 then (a,b,c,d,e,f,g,h)
        else
          let
            val s1 = xorb (xorb (rotr e 6) (rotr e 11)) (rotr e 25)
            val ch = xorb (andb e f) (andb (notb e) g)
            val t1 = add32 (add32 (add32 (add32 h s1) ch) (Vector.sub k i)) (Array.sub w i)
            val s0 = xorb (xorb (rotr a 2) (rotr a 13)) (rotr a 22)
            val maj = xorb (xorb (andb a b) (andb a c)) (andb b c)
            val t2 = add32 s0 maj
          in
            round (i + 1, add32 t1 t2, a, b, c, add32 d t1, e, f, g)
          end
      val (a,b,c,d,e,f,g,h) = round (0, h0,h1,h2,h3,h4,h5,h6,h7)
    in
      (add32 h0 a, add32 h1 b, add32 h2 c, add32 h3 d,
       add32 h4 e, add32 h5 f, add32 h6 g, add32 h7 h)
    end

  fun digestWords msg =
    let
      val blocks = chunk16 (padded msg)
      val init = (0wx6a09e667,0wxbb67ae85,0wx3c6ef372,0wxa54ff53a,
                  0wx510e527f,0wx9b05688c,0wx1f83d9ab,0wx5be0cd19)
    in
      List.foldl (fn blk => fn st => processBlock (st, blk)) init blocks
    end

  fun wordBytes w =
    String.implode
      (List.map
        (fn sh => Char.chr (Word64.toInt (andb (lsr w sh) 0wxFF)))
        [24, 16, 8, 0])

  fun toList (a,b,c,d,e,f,g,h) = [a,b,c,d,e,f,g,h]

  fun digest msg =
    String.concat (List.map wordBytes (toList (digestWords msg)))
end

(* ================================================================== *)
(* HMAC (RFC 2104), SHA-256 instance                                   *)
(* ================================================================== *)

structure Hmac = struct
  fun xorByte pad c =
    Char.chr (Word8.toInt (Word8.xorb (Word8.fromInt (Char.ord c)) (Word8.fromInt pad)))

  fun xorConst pad s = String.translate (fn c => xorByte pad c) s

  fun hmacWith hash blockSize key message =
    let
      val k0a = if String.size key > blockSize then hash key else key
      val k0 = k0a ^ String.implode (List.tabulate (blockSize - String.size k0a) (fn _ => Char.chr 0))
      val ipad = xorConst 0x36 k0
      val opad = xorConst 0x5c k0
      val inner = hash (ipad ^ message)
    in
      hash (opad ^ inner)
    end

  fun hmacSha256 key message = hmacWith Sha256.digest 64 key message
end

(* ================================================================== *)
(* HKDF (RFC 5869) over HMAC-SHA-256                                   *)
(* ================================================================== *)

structure Kdf = struct
  exception Kdf string

  val hashLen = 32

  (* (salt, ikm) -> prk *)
  fun hkdfExtract (salt, ikm) =
    let val salt2 = if String.size salt = 0
                    then String.implode (List.tabulate hashLen (fn _ => Char.chr 0))
                    else salt
    in Hmac.hmacSha256 salt2 ikm end

  (* (prk, info, len) -> okm *)
  fun hkdfExpand (prk, info, len) =
    let
      val hl = hashLen
      val n  = (len + hl - 1) div hl
      val () = if len < 0 then raise Kdf "expand: negative length" else ()
      val () = if n > 255 then raise Kdf "expand: length exceeds 255*HashLen" else ()
      fun loop (i, prev, acc) =
        if i > n then String.concat (List.rev acc)
        else
          let val t = Hmac.hmacSha256 prk (prev ^ info ^ String.str (Char.chr i))
          in loop (i + 1, t, t :: acc) end
      val okm = loop (1, "", [])
    in String.substring okm 0 len end

  (* (salt, ikm, info, len) -> okm *)
  fun hkdfDerive (salt, ikm, info, len) =
    hkdfExpand (hkdfExtract (salt, ikm), info, len)
end
