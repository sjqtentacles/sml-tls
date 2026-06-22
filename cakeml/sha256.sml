(* sha256.sml — CakeML port of sml-codec/sha256.sml

   Dialect gaps addressed (see SPIKE_REPORT.md for details):
   - CakeML has no Word32 module: use Word64 and mask to 32 bits after every
     arithmetic op (xor/and/or are width-preserving; only + and << can exceed).
   - CakeML has no StringCvt / Word32.fmt / StringCvt.padLeft: hand-rolled hex.
   - CakeML has no Char.toLower: hand-rolled via Char.ord/Char.chr.
   - CakeML has no IntInf: CakeML's int is already arbitrary precision, so the
     bit-length computation uses plain int (msg length is bounded by memory).
   - CakeML constructors must be capitalised: True/False/None/Some/Ref. This
     file doesn't use datatypes beyond bool/option, but uses True/False.
   - CakeML has no signatures/ascription: drop ":> SHA256".
   - CakeML lacks let-polymorphism: not triggered here (no polymorphic let).
   - CakeML right-to-left eval order: no reliance on side-effect ordering in
     pure code; array updates are sequenced with ; inside let.

   The original sml-codec source is untouched. *)

structure Sha256 = struct

  (* 32-bit word emulation via Word64 + mask. All Word32 ops in the original
     become Word64 ops followed by masking where needed. *)
  val mask32 : Word64.word = 0wxFFFFFFFF
  infix 6 ++
  fun op ++ (a, b) = Word64.andb (Word64.+ (a, b), mask32)
  val andb = Word64.andb
  val orb  = Word64.orb
  val xorb = Word64.xorb
  infix andb orb xorb
  fun << (a, b) = Word64.andb (Word64.<< (a, b), mask32)
  fun >> (a, b) = Word64.>> (a, b)
  infix << >>
  fun notb w = Word64.xorb (w, mask32)

  fun rotr (w, n : int) =
    Word64.orb (Word64.>> (w, n), Word64.andb (Word64.<< (w, 64 - n), mask32))

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

  (* Padding. CakeML int is arbitrary precision so IntInf is unnecessary. *)
  fun padded (msg : string) : Word64.word list =
    let
      val len = String.size msg
      val bitLen = len * 8
      val withOne = msg ^ String.str (Char.chr 0x80)
      val padZeros : int =
        let val m = String.size withOne mod 64
        in if m <= 56 then 56 - m else 120 - m end
      val zeros = String.implode (List.tabulate (padZeros, fn _ => Char.chr 0))
      fun lenByte (i : int) =
        Char.chr (((bitLen >> (i * 8)) mod 256))
      val lenBytes = String.implode (List.map lenByte [7,6,5,4,3,2,1,0])
      val full = withOne ^ zeros ^ lenBytes
      val n = String.size full
      fun word (i : int) =
        let fun b (kk : int) =
              Word64.fromInt (Char.ord (String.sub (full, i + kk)))
        in Word64.orb (Word64.orb (Word64.<< (b 0, 24), Word64.<< (b 1, 16)),
                       Word64.orb (Word64.<< (b 2, 8), b 3))
        end
      fun loop (i : int) acc =
        if i >= n then List.rev acc else loop (i + 4) (word i :: acc)
    in
      loop 0 []
    end

  fun chunk16 ws =
    case ws of
        [] => []
      | _ =>
          let
            fun take 0 xs acc = (List.rev acc, xs)
              | take (j : int) (x :: xs) acc = take (j - 1) xs (x :: acc)
              | take _ [] acc = (List.rev acc, [])
            val (blk, rest) = take 16 ws []
          in blk :: chunk16 rest end

  fun processBlock ((h0,h1,h2,h3,h4,h5,h6,h7), block) =
    let
      val w = Array.array (64, 0w0 : Word64.word)
      val _ = List.foldl (fn (x, i) => (Array.update (w, i, x); i + 1)) 0 block
      fun extend (i : int) =
        if i >= 64 then ()
        else
          let
            val w15 = Array.sub (w, i-15)
            val w2  = Array.sub (w, i-2)
            val s0 = xorb (xorb (rotr (w15, 7), rotr (w15, 18)), >> (w15, 3))
            val s1 = xorb (xorb (rotr (w2, 17), rotr (w2, 19)), >> (w2, 10))
          in
            Array.update (w, i,
              Array.sub (w, i-16) ++ s0 ++ Array.sub (w, i-7) ++ s1);
            extend (i + 1)
          end
      val () = extend 16

      fun round (i : int, a, b, c, d, e, f, g, h) =
        if i >= 64 then (a,b,c,d,e,f,g,h)
        else
          let
            val s1 = xorb (xorb (rotr (e, 6), rotr (e, 11)), rotr (e, 25))
            val ch = xorb (andb (e, f), andb (notb e, g))
            val t1 = h ++ s1 ++ ch ++ Vector.sub (k, i) ++ Array.sub (w, i)
            val s0 = xorb (xorb (rotr (a, 2), rotr (a, 13)), rotr (a, 22))
            val maj = xorb (xorb (andb (a, b), andb (a, c)), andb (b, c))
            val t2 = s0 ++ maj
          in
            round (i + 1, t1 ++ t2, a, b, c, d ++ t1, e, f, g)
          end
      val (a,b,c,d,e,f,g,h) = round (0, h0,h1,h2,h3,h4,h5,h6,h7)
    in
      (h0 ++ a, h1 ++ b, h2 ++ c, h3 ++ d, h4 ++ e, h5 ++ f, h6 ++ g, h7 ++ h)
    end

  fun digestWords msg =
    let
      val blocks = chunk16 (padded msg)
      val init = (0wx6a09e667,0wxbb67ae85,0wx3c6ef372,0wxa54ff53a,
                  0wx510e527f,0wx9b05688c,0wx1f83d9ab,0wx5be0cd19)
    in
      List.foldl (fn (blk, st) => processBlock (st, blk)) init blocks
    end

  fun wordBytes w =
    String.implode
      (List.map
        (fn (sh : int) =>
           Char.chr (Word64.toInt (andb (>> (w, sh), 0wxFF))))
        [24, 16, 8, 0])

  fun toList (a,b,c,d,e,f,g,h) = [a,b,c,d,e,f,g,h]

  fun digest msg =
    String.concat (List.map wordBytes (toList (digestWords msg)))

  (* Hand-rolled hex: CakeML has no StringCvt / Word32.fmt / padLeft. *)
  fun hexDigit n =
    if n < 10 then Char.chr (n + Char.ord #"0")
    else Char.chr (n - 10 + Char.ord #"a")

  fun hexByte w =
    String.implode
      [hexDigit (Word64.toInt (>> (w, 4)) mod 16),
       hexDigit (Word64.toInt w mod 16)]

  fun hexWord w =
    String.concat (List.map (fn sh => hexByte (>> (w, sh))) [24, 16, 8, 0])

  fun hexDigest msg =
    String.concat (List.map hexWord (toList (digestWords msg)))

end
