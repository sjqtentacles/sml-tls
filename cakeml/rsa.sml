(* rsa.sml -- CakeML port of sml-rsa (RFC 8017 / PKCS#1 v2.2).

   RSA primitives (RSAEP/RSADP via CRT), the padding layers
   (EMSA-PKCS1-v1_5, EMSA-PSS, EME-OAEP, EME-PKCS1-v1_5), I2OSP/OS2IP,
   MGF1, modular inverse, and the PKCS#1 / SPKI / PKCS#8 key codecs built
   on the vendored Asn1/Pem.  Hashes come from the vendored Sha256.

   The original carries every integer in the vendored arbitrary-precision
   BigInt.  CakeML's native `int` is already arbitrary precision (see the
   asn1 port, which made the same choice), so this port uses native `int`
   throughout and interoperates directly with the native-int Asn1.Int.

   Dialect-gap fixes (see rsa_PORT_NOTES.md):
     - records `{n,e}` / `{...}` -> curried-constructor datatypes
       (Pub, Priv) and tuple-argument functions (no `#field` selectors)
     - BigInt replaced by native `int`; B.modpow/B.divMod/B.quotRem/...
       -> native modpow / div / mod / arithmetic
     - no signature ascription
     - multi-clause `fun ... | ...` -> single clause + `case`
     - single-arg `fn`; `SOME`/`NONE`/`true`/`false` -> Some/None/True/False
     - tupled basis calls (String.sub/substring/extract) made curried
     - char comparisons via Char.>=/Char.<= (no polymorphic compare)
     - byte XOR via Word64 (CakeML `int` has no bitwise xor)
     - Word/IntInf.* shift+mask ops -> Word64
     - key generation (Miller-Rabin) and SHA-1/SHA-512 hashes are out of
       scope for this port (no primality test / those hashes in the tower);
       hashBytes implements SHA-256, the one the test vectors and the
       X.509 chain use.
*)

structure Rsa = struct

  datatype hash = SHA1 | SHA256 | SHA512

  (* n e *)
  datatype pubkey = Pub int int
  (* n e d p q dp dq qinv *)
  datatype privkey = Priv int int int int int int int int

  exception RSA string

  (* ---------------- small numeric / byte helpers ---------------- *)

  fun byte n = String.str (Char.chr n)
  fun ordOf (s, i) = Char.ord (String.sub s i)
  fun zeros n = String.implode (List.tabulate n (fn _ => Char.chr 0))

  (* non-negative remainder x mod m (m > 0): CakeML mod follows SML *)
  fun modNN (x, m) = x mod m

  (* ---- hex ---- *)
  val hexChars = "0123456789abcdef"
  fun toHex s =
    String.concat
      (List.map (fn c =>
         let val n = Char.ord c
         in String.implode [String.sub hexChars (n div 16), String.sub hexChars (n mod 16)] end)
       (String.explode s))

  fun isSpace c =
    Char.= c #" " orelse Char.= c #"\n" orelse Char.= c #"\t" orelse Char.= c #"\r"

  fun fromHex s =
    let
      fun hv c =
        if Char.>= c #"0" andalso Char.<= c #"9" then Char.ord c - 48
        else if Char.>= c #"a" andalso Char.<= c #"f" then Char.ord c - 87
        else if Char.>= c #"A" andalso Char.<= c #"F" then Char.ord c - 55
        else raise RSA "fromHex: bad digit"
      val cs = List.filter (fn c => not (isSpace c)) (String.explode s)
      fun loop xs =
        case xs of
          [] => []
        | [_] => raise RSA "fromHex: odd length"
        | (a :: b :: rest) => Char.chr (hv a * 16 + hv b) :: loop rest
    in String.implode (loop cs) end

  (* ---- modular exponentiation: c = b^e mod m (square-and-multiply) ---- *)
  fun modpow (b, e, m) =
    let
      fun loop (base, e, acc) =
        if e = 0 then acc
        else
          let val acc2 = if e mod 2 = 1 then (acc * base) mod m else acc
          in loop ((base * base) mod m, e div 2, acc2) end
    in loop (b mod m, e, 1) end

  (* ---- I2OSP / OS2IP ---- *)

  fun i2osp (x, len) =
    if x < 0 then raise RSA "I2OSP: negative integer"
    else
      let
        fun digits (x, acc) =
          if x = 0 then acc
          else digits (x div 256, (x mod 256) :: acc)
        val ds = digits (x, [])
        val l = List.length ds
      in
        if l > len then raise RSA "I2OSP: integer too large for the requested length"
        else zeros (len - l) ^ String.implode (List.map Char.chr ds)
      end

  fun os2ip s =
    let
      val n = String.size s
      fun loop (i, acc) =
        if i = n then acc
        else loop (i + 1, acc * 256 + ordOf (s, i))
    in loop (0, 0) end

  (* bit length of n >= 0 *)
  fun bitLength n =
    let fun loop (x, acc) = if x = 0 then acc else loop (x div 2, acc + 1)
    in loop (n, 0) end

  fun modulusBytesN n = (bitLength n + 7) div 8
  fun modulusBytes (Pub n _) = modulusBytesN n
  fun pubOf (Priv n e _ _ _ _ _ _) = Pub n e

  (* byte-wise XOR (CakeML int has no xor; go through Word64) *)
  fun xorByte (a, b) =
    Word64.toInt (Word64.xorb (Word64.fromInt a) (Word64.fromInt b))
  fun xorStr (a, b) =
    String.implode
      (List.tabulate (String.size a) (fn i => Char.chr (xorByte (ordOf (a, i), ordOf (b, i)))))

  (* zero the leftmost [nbits] (0..7) bits of the first byte of s *)
  fun clearTopBits (s, nbits) =
    if nbits = 0 then s
    else
      let
        val mask = Word64.toInt (Word64.>> (0wxFF : Word64.word) nbits)
        val b0 = Word64.toInt (Word64.andb (Word64.fromInt (ordOf (s, 0))) (Word64.fromInt mask))
      in byte b0 ^ String.extract s 1 None end

  fun topBitsZero (s, nbits) =
    nbits = 0 orelse ordOf (s, 0) = ordOf (clearTopBits (s, nbits), 0)

  (* ---- hashes (SHA-256 only in the CakeML tower) ---- *)
  fun hashBytes h m =
    case h of
      SHA256 => Sha256.digest m
    | SHA1   => raise RSA "SHA-1 not available in the CakeML port"
    | SHA512 => raise RSA "SHA-512 not available in the CakeML port"
  fun hashLen h = case h of SHA1 => 20 | SHA256 => 32 | SHA512 => 64
  fun hashOid h =
    case h of
      SHA1   => [1, 3, 14, 3, 2, 26]
    | SHA256 => [2, 16, 840, 1, 101, 3, 4, 2, 1]
    | SHA512 => [2, 16, 840, 1, 101, 3, 4, 2, 3]

  (* MGF1 (RFC 8017 App. B.2.1) *)
  fun mgf1 (hash, seed, len) =
    let
      val hLen = hashLen hash
      fun loop (counter, acc, got) =
        if got >= len then String.substring (String.concat (List.rev acc)) 0 len
        else
          let val block = hashBytes hash (seed ^ i2osp (counter, 4))
          in loop (counter + 1, block :: acc, got + hLen) end
    in loop (0, [], 0) end

  (* ---- extended Euclid / modular inverse ---- *)
  fun modInverse (a, m) =
    let
      fun ext (r0, s0, r1, s1) =
        if r1 = 0 then (r0, s0)
        else
          let val q = r0 div r1
              val r2 = r0 - q * r1
              val s2 = s0 - q * s1
          in ext (r1, s1, r2, s2) end
      val (g, x) = ext (modNN (a, m), 1, m, 0)
    in
      if g <> 1 then raise RSA "modInverse: value is not invertible"
      else modNN (x, m)
    end

  (* ---------------- RSA primitives ---------------- *)

  fun rsaPublic (Pub n e, m) =
    if m < 0 orelse m >= n then raise RSA "message representative out of range"
    else modpow (m, e, n)

  fun rsaPrivate (Priv n e d p q dp dq qinv, c) =
    if c < 0 orelse c >= n then raise RSA "ciphertext representative out of range"
    else
      let
        val m1 = modpow (c, dp, p)
        val m2 = modpow (c, dq, q)
        val h  = modNN (qinv * modNN (m1 - m2, p), p)
      in m2 + q * h end

  (* ---------------- EMSA-PKCS1-v1_5 signatures ---------------- *)

  fun digestInfo (hash, msg) =
    Asn1.encode
      (Asn1.Seq [ Asn1.Seq [ Asn1.Oid (hashOid hash), Asn1.Null ]
                , Asn1.Bytes (hashBytes hash msg) ])

  fun emsaPkcs1v15 (hash, msg, emLen) =
    let
      val t = digestInfo (hash, msg)
      val tLen = String.size t
      val () = if emLen < tLen + 11
               then raise RSA "intended encoded message length too short" else ()
      val ps = String.implode (List.tabulate (emLen - tLen - 3) (fn _ => Char.chr 0xFF))
    in byte 0 ^ byte 1 ^ ps ^ byte 0 ^ t end

  fun sign (priv, hash, msg) =
    let
      val Priv n _ _ _ _ _ _ _ = priv
      val k = modulusBytesN n
      val em = emsaPkcs1v15 (hash, msg, k)
    in i2osp (rsaPrivate (priv, os2ip em), k) end

  fun verify (pub, hash, msg, sgn) =
    (let
       val Pub n _ = pub
       val k = modulusBytesN n
     in
       String.size sgn = k
       andalso
       let val m = rsaPublic (pub, os2ip sgn)
           val em = i2osp (m, k)
       in em = emsaPkcs1v15 (hash, msg, k) end
     end) handle _ => False

  (* ---------------- EMSA-PSS signatures ---------------- *)

  fun emsaPssEncode (hash, msg, salt, emBits) =
    let
      val hLen = hashLen hash
      val sLen = String.size salt
      val emLen = (emBits + 7) div 8
      val () = if emLen < hLen + sLen + 2 then raise RSA "PSS: encoding error" else ()
      val mHash = hashBytes hash msg
      val mPrime = zeros 8 ^ mHash ^ salt
      val h = hashBytes hash mPrime
      val ps = zeros (emLen - sLen - hLen - 2)
      val db = ps ^ byte 1 ^ salt
      val maskedDB = xorStr (db, mgf1 (hash, h, emLen - hLen - 1))
      val maskedDB2 = clearTopBits (maskedDB, 8 * emLen - emBits)
    in maskedDB2 ^ h ^ byte 0xBC end

  fun signPss (priv, hash, salt, msg) =
    let
      val Priv n _ _ _ _ _ _ _ = priv
      val emBits = bitLength n - 1
      val em = emsaPssEncode (hash, msg, salt, emBits)
    in i2osp (rsaPrivate (priv, os2ip em), modulusBytesN n) end

  fun verifyPss (pub, hash, saltLen, msg, sgn) =
    (let
       val Pub n _ = pub
       val k = modulusBytesN n
       val emBits = bitLength n - 1
       val emLen = (emBits + 7) div 8
       val hLen = hashLen hash
     in
       String.size sgn = k
       andalso
       let
         val em = i2osp (rsaPublic (pub, os2ip sgn), emLen)
         val dbLen = emLen - hLen - 1
       in
         emLen >= hLen + saltLen + 2
         andalso ordOf (em, emLen - 1) = 0xBC
         andalso
         let
           val maskedDB = String.substring em 0 dbLen
           val h = String.substring em dbLen hLen
           val topBits = 8 * emLen - emBits
         in
           topBitsZero (maskedDB, topBits)
           andalso
           let
             val db = clearTopBits (xorStr (maskedDB, mgf1 (hash, h, dbLen)), topBits)
             val psN = dbLen - saltLen - 1
             fun zeroPrefix i = i >= psN orelse (ordOf (db, i) = 0 andalso zeroPrefix (i + 1))
           in
             zeroPrefix 0 andalso ordOf (db, psN) = 1
             andalso
             let
               val salt = String.extract db (psN + 1) None
               val mHash = hashBytes hash msg
               val mPrime = zeros 8 ^ mHash ^ salt
             in h = hashBytes hash mPrime end
           end
         end
       end
     end) handle _ => False

  (* ---------------- EME-OAEP encryption ---------------- *)

  fun encryptOaep (pub, hash, label, seed, msg) =
    let
      val Pub n _ = pub
      val k = modulusBytesN n
      val hLen = hashLen hash
      val mLen = String.size msg
      val () = if String.size seed <> hLen then raise RSA "OAEP: seed must be hLen bytes" else ()
      val () = if mLen > k - 2 * hLen - 2 then raise RSA "OAEP: message too long" else ()
      val lHash = hashBytes hash label
      val db = lHash ^ zeros (k - mLen - 2 * hLen - 2) ^ byte 1 ^ msg
      val maskedDB = xorStr (db, mgf1 (hash, seed, k - hLen - 1))
      val maskedSeed = xorStr (seed, mgf1 (hash, maskedDB, hLen))
      val em = byte 0 ^ maskedSeed ^ maskedDB
    in i2osp (rsaPublic (pub, os2ip em), k) end

  fun decryptOaep (priv, hash, label, ct) =
    let
      val Priv n _ _ _ _ _ _ _ = priv
      val k = modulusBytesN n
      val hLen = hashLen hash
      val () = if String.size ct <> k orelse k < 2 * hLen + 2
               then raise RSA "OAEP: decryption error" else ()
      val em = i2osp (rsaPrivate (priv, os2ip ct), k)
      val lHash = hashBytes hash label
      val y = ordOf (em, 0)
      val maskedSeed = String.substring em 1 hLen
      val maskedDB = String.substring em (1 + hLen) (k - hLen - 1)
      val seed = xorStr (maskedSeed, mgf1 (hash, maskedDB, hLen))
      val db = xorStr (maskedDB, mgf1 (hash, seed, k - hLen - 1))
      val lHash2 = String.substring db 0 hLen
      fun findOne i =
        if i >= String.size db then raise RSA "OAEP: decryption error"
        else
          let val v = ordOf (db, i)
          in if v = 1 then i
             else if v = 0 then findOne (i + 1)
             else raise RSA "OAEP: decryption error"
          end
      val sep = findOne hLen
    in
      if y <> 0 orelse lHash2 <> lHash then raise RSA "OAEP: decryption error"
      else String.extract db (sep + 1) None
    end

  (* ---------------- EME-PKCS1-v1_5 encryption ---------------- *)

  fun nonZeroPad (randomBytes, need) =
    let
      fun go (acc, n) =
        if n = 0 then String.implode (List.rev acc)
        else
          let
            val chunk = randomBytes n
            val () = if String.size chunk = 0 then raise RSA "randomBytes returned no bytes" else ()
            fun take (cs, acc, n) =
              if n = 0 then (acc, 0)
              else
                case cs of
                  [] => (acc, n)
                | (c :: rest) =>
                    if Char.= c (Char.chr 0) then take (rest, acc, n)
                    else take (rest, c :: acc, n - 1)
            val (acc2, n2) = take (String.explode chunk, acc, n)
          in go (acc2, n2) end
    in go ([], need) end

  fun encrypt (pub, msg, randomBytes) =
    let
      val Pub n _ = pub
      val k = modulusBytesN n
      val mLen = String.size msg
      val () = if mLen > k - 11 then raise RSA "message too long for PKCS#1 v1.5" else ()
      val ps = nonZeroPad (randomBytes, k - mLen - 3)
      val em = byte 0 ^ byte 2 ^ ps ^ byte 0 ^ msg
    in i2osp (rsaPublic (pub, os2ip em), k) end

  fun decrypt (priv, ct) =
    let
      val Priv n _ _ _ _ _ _ _ = priv
      val k = modulusBytesN n
      val () = if String.size ct <> k orelse k < 11 then raise RSA "decryption error" else ()
      val em = i2osp (rsaPrivate (priv, os2ip ct), k)
      val () = if ordOf (em, 0) <> 0 orelse ordOf (em, 1) <> 2 then raise RSA "decryption error" else ()
      fun findZero i =
        if i >= k then raise RSA "decryption error"
        else if ordOf (em, i) = 0 then i else findZero (i + 1)
      val z = findZero 2
      val () = if z < 10 then raise RSA "decryption error" else ()
    in String.extract em (z + 1) None end

  (* ---------------- DER / PEM key import & export ---------------- *)

  val rsaOid = [1, 2, 840, 113549, 1, 1, 1]
  val rsaAlgId = Asn1.Seq [ Asn1.Oid rsaOid, Asn1.Null ]

  fun encodePublicDer (Pub n e) =
    Asn1.encode (Asn1.Seq [ Asn1.Int n, Asn1.Int e ])

  fun decodePublicDer s =
    case Asn1.decode s of
      Asn1.Seq [ Asn1.Int n, Asn1.Int e ] => Pub n e
    | _ => raise RSA "bad RSAPublicKey"

  fun encodePrivateDer (Priv n e d p q dp dq qinv) =
    Asn1.encode
      (Asn1.Seq [ Asn1.Int 0, Asn1.Int n, Asn1.Int e, Asn1.Int d
                , Asn1.Int p, Asn1.Int q
                , Asn1.Int dp, Asn1.Int dq, Asn1.Int qinv ])

  fun decodePrivateDer s =
    case Asn1.decode s of
      Asn1.Seq [ Asn1.Int _, Asn1.Int n, Asn1.Int e, Asn1.Int d
               , Asn1.Int p, Asn1.Int q, Asn1.Int dp, Asn1.Int dq, Asn1.Int qinv ] =>
        Priv n e d p q dp dq qinv
    | _ => raise RSA "bad RSAPrivateKey"

  fun encodeSpkiDer pub =
    Asn1.encode (Asn1.Seq [ rsaAlgId, Asn1.BitString (encodePublicDer pub) ])

  fun decodeSpkiDer s =
    case Asn1.decode s of
      Asn1.Seq (Asn1.Seq (Asn1.Oid oid :: _) :: Asn1.BitString bits :: _) =>
        if oid = rsaOid then decodePublicDer bits
        else raise RSA "SubjectPublicKeyInfo: not an RSA key"
    | _ => raise RSA "bad SubjectPublicKeyInfo"

  fun encodePkcs8Der priv =
    Asn1.encode (Asn1.Seq [ Asn1.Int 0, rsaAlgId, Asn1.Bytes (encodePrivateDer priv) ])

  fun decodePkcs8Der s =
    case Asn1.decode s of
      Asn1.Seq (Asn1.Int _ :: Asn1.Seq (Asn1.Oid oid :: _) :: Asn1.Bytes octets :: _) =>
        if oid = rsaOid then decodePrivateDer octets
        else raise RSA "PKCS#8 PrivateKeyInfo: not an RSA key"
    | _ => raise RSA "bad PKCS#8 PrivateKeyInfo"

  fun encodePublicPem pub = Pem.encode ("PUBLIC KEY", encodeSpkiDer pub)
  fun encodePrivatePem priv = Pem.encode ("PRIVATE KEY", encodePkcs8Der priv)

  fun firstBlock s =
    case Pem.decode s of
      [] => raise RSA "no PEM block found"
    | (b :: _) => b

  fun decodePublicPem s =
    let val (label, der) = firstBlock s
    in
      if label = "PUBLIC KEY" then decodeSpkiDer der
      else if label = "RSA PUBLIC KEY" then decodePublicDer der
      else raise RSA ("unexpected PEM label for a public key: " ^ label)
    end

  fun decodePrivatePem s =
    let val (label, der) = firstBlock s
    in
      if label = "PRIVATE KEY" then decodePkcs8Der der
      else if label = "RSA PRIVATE KEY" then decodePrivateDer der
      else raise RSA ("unexpected PEM label for a private key: " ^ label)
    end

end
