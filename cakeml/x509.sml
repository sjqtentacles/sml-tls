(* x509.sml -- CakeML port of sml-x509 (RFC 5280 certificate parsing +
   RSA signature verification).

   A small offset-aware DER reader (not the strict Asn1 common-subset
   decoder) hands back the verbatim byte-slice of every element via `raw`,
   so signatures over the original tbsCertificate bytes verify exactly, and
   so real-world types outside the common subset (UTCTime/GeneralizedTime,
   IA5String, IMPLICIT primitive context tags) parse.  Pem unwraps
   CERTIFICATE blocks; Rsa does the PKCS#1 v1.5 / PSS verification.

   Like the rest of the CakeML tower this uses native `int` (the serial
   number too -- CakeML `int` is arbitrary precision).

   Dialect-gap fixes (see x509_PORT_NOTES.md):
     - records are a *parse error* in cake: the `node`, `time`, `cert`
       records and the `{hash,saltLen}`/`{ca,pathLen}`/attribute/extension
       records all became datatypes / tuples; every `#field` selector became
       a constructor accessor or a tuple destructure.
     - record-argument functions (verifySignature {cert,issuer}, verifyChain
       {...}) became tuple-argument functions.
     - BigInt -> native `int`; multi-clause `fun ... | ...` -> `case`;
       SOME/NONE/true/false -> Some/None/True/False; tupled basis calls
       curried; char compares via Char.*; Word.* bit ops -> Word64.*;
       no signature ascription.
*)

structure X509 = struct

  exception X509 string

  (* ===================== parsed types ===================== *)

  (* year month day hour minute second *)
  datatype time = Time int int int int int int

  (* (oid, value) *)
  type attribute = int list * string
  type name = attribute list

  (* (oid, critical, value) *)
  type extension = int list * bool * string

  datatype sigAlg =
      Sha1WithRsa | Sha256WithRsa | Sha384WithRsa | Sha512WithRsa
    | RsaPss Rsa.hash int                    (* hash, saltLen *)
    | EcdsaWithSha256 | EcdsaWithSha384 | EcdsaWithSha512
    | Ed25519Sig | UnknownSigAlg (int list)

  datatype keyAlg =
      RsaKey | EcKey (int list) | Ed25519Key | UnknownKeyAlg (int list)

  datatype verifyResult = Verified | Failed | Unsupported string
  datatype chainResult = ChainOk | ChainError string

  (* der tbsDer version serialContent serial sigAlg issuer issuerDer
     subject subjectDer validity spkiDer keyAlg signatureValue extensions
     where validity = (notBefore, notAfter) *)
  datatype cert =
    Cert string string int string int sigAlg
         name string name string (time * time) string
         keyAlg string (extension list)

  (* ===================== DER reader ===================== *)

  fun byteAt (s, i) = Char.ord (String.sub s i)

  (* cls constructed tag start contentOff contentLen endOff *)
  datatype node = Node int bool int int int int int
  fun nCls   (Node c _ _ _ _ _ _) = c
  fun nCon   (Node _ k _ _ _ _ _) = k
  fun nTag   (Node _ _ t _ _ _ _) = t
  fun nStart (Node _ _ _ s _ _ _) = s
  fun nCOff  (Node _ _ _ _ co _ _) = co
  fun nCLen  (Node _ _ _ _ _ l _) = l
  fun nEnd   (Node _ _ _ _ _ _ e) = e

  fun readLen (s, pos) =
    let val size = String.size s
        val () = if pos >= size then raise X509 "truncated length" else ()
        val b0 = byteAt (s, pos)
    in
      if b0 < 0x80 then (b0, pos + 1)
      else
        let val n = b0 - 0x80
            val () = if n = 0 then raise X509 "indefinite length not allowed" else ()
            val () = if pos + n >= size then raise X509 "truncated long-form length" else ()
            fun loop (i, acc) =
              if i = n then acc else loop (i + 1, acc * 256 + byteAt (s, pos + 1 + i))
        in (loop (0, 0), pos + 1 + n) end
    end

  fun readTLV (s, pos) =
    let
      val size = String.size s
      val () = if pos >= size then raise X509 "truncated identifier" else ()
      val id = byteAt (s, pos)
      val cls = id div 64
      val constructed = (id div 32) mod 2 = 1
      val low = id mod 32
      val (tag, idEnd) =
        if low <> 31 then (low, pos + 1)
        else
          let fun loop (i, acc) =
                let val () = if i >= size then raise X509 "truncated high tag" else ()
                    val b = byteAt (s, i)
                    val acc2 = acc * 128 + (b mod 128)
                in if b < 0x80 then (acc2, i + 1) else loop (i + 1, acc2) end
          in loop (pos + 1, 0) end
      val (len, contentOff) = readLen (s, idEnd)
      val endOff = contentOff + len
      val () = if endOff > size then raise X509 "length exceeds input" else ()
    in Node cls constructed tag pos contentOff len endOff end

  fun content (s, n) = String.substring s (nCOff n) (nCLen n)
  fun raw (s, n) = String.substring s (nStart n) (nEnd n - nStart n)

  fun children (s, n) =
    let val stop = nEnd n
        fun loop pos =
          if pos >= stop then []
          else let val c = readTLV (s, pos) in c :: loop (nEnd c) end
    in loop (nCOff n) end

  (* ---- small primitive decoders over a node ---- *)

  fun uintOf (s, n) =
    let val c = content (s, n)
        fun loop (i, acc) =
          if i >= String.size c then acc
          else loop (i + 1, acc * 256 + Char.ord (String.sub c i))
    in loop (0, 0) end

  fun boolOf (s, n) =
    String.size (content (s, n)) > 0 andalso byteAt (content (s, n), 0) <> 0

  fun oidOf (s, n) =
    let
      val c = content (s, n)
      val len = String.size c
      val () = if len = 0 then raise X509 "empty OID" else ()
      fun readSub (j, v) =
        if j >= len then raise X509 "truncated OID"
        else let val b = byteAt (c, j)
                 val v2 = v * 128 + (b mod 128)
             in if b < 0x80 then (v2, j + 1) else readSub (j + 1, v2) end
      fun loop (i, acc) =
        if i >= len then List.rev acc
        else let val (v, nx) = readSub (i, 0) in loop (nx, v :: acc) end
      val subs = loop (0, [])
    in
      case subs of
        (first :: rest) =>
          let val (a0, a1) =
                if first < 40 then (0, first)
                else if first < 80 then (1, first - 40)
                else (2, first - 80)
          in a0 :: a1 :: rest end
      | [] => raise X509 "empty OID"
    end

  fun bitStringOf (s, n) =
    let val c = content (s, n)
    in if String.size c = 0 then "" else String.extract c 1 None end

  fun bigUnsigned bytes =
    let fun loop (i, acc) =
          if i >= String.size bytes then acc
          else loop (i + 1, acc * 256 + byteAt (bytes, i))
    in loop (0, 0) end

  fun toHexLower s =
    let val d = "0123456789abcdef"
        fun hx c = let val x = Char.ord c
                   in String.implode [String.sub d (x div 16), String.sub d (x mod 16)] end
    in String.concat (List.map hx (String.explode s)) end

  (* ===================== OID tables ===================== *)

  val oidCommonName     = [2,5,4,3]
  val oidBasicConstr    = [2,5,29,19]
  val oidKeyUsage       = [2,5,29,15]
  val oidExtKeyUsage    = [2,5,29,37]
  val oidSubjectAltName = [2,5,29,17]
  val oidSubjectKeyId   = [2,5,29,14]
  val oidAuthKeyId      = [2,5,29,35]

  fun hashOfOid oid =
    if oid = [1,3,14,3,2,26] then Some Rsa.SHA1
    else if oid = [2,16,840,1,101,3,4,2,1] then Some Rsa.SHA256
    else if oid = [2,16,840,1,101,3,4,2,3] then Some Rsa.SHA512
    else None

  (* ===================== field parsers ===================== *)

  fun parseName (s, nameNode) =
    let
      val rdns = children (s, nameNode)
      fun fromAtv atvNode =
        case children (s, atvNode) of
          (oidN :: valN :: _) => (oidOf (s, oidN), content (s, valN))
        | _ => raise X509 "malformed AttributeTypeAndValue"
      fun fromSet setNode = List.map fromAtv (children (s, setNode))
    in List.concat (List.map fromSet rdns) end

  fun parseTime (s, tNode) =
    let
      val c = content (s, tNode)
      fun d2 i = (byteAt (c, i) - 48) * 10 + (byteAt (c, i + 1) - 48)
    in
      if nTag tNode = 23 then
        let val yy = d2 0
            val year = if yy < 50 then 2000 + yy else 1900 + yy
        in Time year (d2 2) (d2 4) (d2 6) (d2 8) (d2 10) end
      else if nTag tNode = 24 then
        Time (d2 0 * 100 + d2 2) (d2 4) (d2 6) (d2 8) (d2 10) (d2 12)
      else raise X509 "unexpected time type"
    end

  fun parseValidity (s, vNode) =
    case children (s, vNode) of
      (nb :: na :: _) => (parseTime (s, nb), parseTime (s, na))
    | _ => raise X509 "malformed Validity"

  (* RSASSA-PSS-params (RFC 4055): returns (hash, saltLen) *)
  fun parsePssParams (s, paramsNode) =
    let
      val kids = children (s, paramsNode)
      fun scan (xs, hash, salt) =
        case xs of
          [] => (hash, salt)
        | (k :: rest) =>
            if nCls k = 2 andalso nTag k = 0 then
              (case children (s, k) of
                 (alg :: _) =>
                   (case children (s, alg) of
                      (oidN :: _) =>
                        (case hashOfOid (oidOf (s, oidN)) of
                           Some h => scan (rest, h, salt)
                         | None => scan (rest, hash, salt))
                    | _ => scan (rest, hash, salt))
               | _ => scan (rest, hash, salt))
            else if nCls k = 2 andalso nTag k = 2 then
              (case children (s, k) of
                 (intN :: _) => scan (rest, hash, uintOf (s, intN))
               | _ => scan (rest, hash, salt))
            else scan (rest, hash, salt)
    in scan (kids, Rsa.SHA1, 20) end

  fun parseSigAlg (s, algNode) =
    case children (s, algNode) of
      (oidN :: rest) =>
        let val oid = oidOf (s, oidN)
        in
          if oid = [1,2,840,113549,1,1,5] then Sha1WithRsa
          else if oid = [1,2,840,113549,1,1,11] then Sha256WithRsa
          else if oid = [1,2,840,113549,1,1,12] then Sha384WithRsa
          else if oid = [1,2,840,113549,1,1,13] then Sha512WithRsa
          else if oid = [1,2,840,113549,1,1,10] then
            (case rest of
               (p :: _) => let val (h, sl) = parsePssParams (s, p) in RsaPss h sl end
             | [] => RsaPss Rsa.SHA1 20)
          else if oid = [1,2,840,10045,4,3,2] then EcdsaWithSha256
          else if oid = [1,2,840,10045,4,3,3] then EcdsaWithSha384
          else if oid = [1,2,840,10045,4,3,4] then EcdsaWithSha512
          else if oid = [1,3,101,112] then Ed25519Sig
          else UnknownSigAlg oid
        end
    | _ => raise X509 "malformed AlgorithmIdentifier"

  fun parseKeyAlg (s, spkiNode) =
    case children (s, spkiNode) of
      (algN :: _) =>
        (case children (s, algN) of
           (oidN :: rest) =>
             let val oid = oidOf (s, oidN)
             in
               if oid = [1,2,840,113549,1,1,1] then RsaKey
               else if oid = [1,2,840,10045,2,1] then
                 (case rest of
                    (p :: _) => (EcKey (oidOf (s, p)) handle _ => EcKey [])
                  | [] => EcKey [])
               else if oid = [1,3,101,112] then Ed25519Key
               else UnknownKeyAlg oid
             end
         | _ => raise X509 "malformed SPKI algorithm")
    | _ => raise X509 "malformed SubjectPublicKeyInfo"

  fun parseExtensions (s, extsSeqNode) =
    let
      fun fromExt extNode =
        case children (s, extNode) of
          (oidN :: rest) =>
            let
              val oid = oidOf (s, oidN)
              val (critical, valNode) =
                case rest of
                  (b :: v :: _) =>
                    if nTag b = 1 andalso nCls b = 0 then (boolOf (s, b), v) else (False, b)
                | (v :: _) => (False, v)
                | [] => raise X509 "extension missing value"
            in (oid, critical, content (s, valNode)) end
        | _ => raise X509 "malformed Extension"
    in List.map fromExt (children (s, extsSeqNode)) end

  (* ===================== top-level parse ===================== *)

  fun parse der =
    let
      val certN = readTLV (der, 0)
      val () = if nEnd certN <> String.size der then raise X509 "trailing bytes" else ()
      val (tbsN, algN, sigN) =
        case children (der, certN) of
          (a :: b :: c :: _) => (a, b, c)
        | _ => raise X509 "Certificate is not a 3-element SEQUENCE"

      val tbsDer = raw (der, tbsN)
      val sa = parseSigAlg (der, algN)
      val sigValue = bitStringOf (der, sigN)

      val tbsKids = children (der, tbsN)
      val (ver, afterVer) =
        case tbsKids of
          (k :: ks) =>
            if nCls k = 2 andalso nTag k = 0 then
              (case children (der, k) of
                 (vN :: _) => (uintOf (der, vN), ks)
               | [] => (0, ks))
            else (0, tbsKids)
        | [] => raise X509 "empty tbsCertificate"

      val (serialN, issuerN, validN, subjectN, spkiN, moreKids) =
        case afterVer of
          (serialN :: sigInnerN :: issuerN :: validN :: subjectN :: spkiN :: more) =>
            (serialN, issuerN, validN, subjectN, spkiN, more)
        | _ => raise X509 "tbsCertificate missing required fields"

      val serialContent = content (der, serialN)
      val serialMag =
        if String.size serialContent > 1 andalso byteAt (serialContent, 0) = 0
        then String.extract serialContent 1 None else serialContent

      val exts =
        case List.find (fn k => nCls k = 2 andalso nTag k = 3) moreKids of
          Some ext3 =>
            (case children (der, ext3) of
               (seqN :: _) => parseExtensions (der, seqN)
             | [] => [])
        | None => []
    in
      Cert der tbsDer ver serialContent (bigUnsigned serialMag) sa
           (parseName (der, issuerN)) (raw (der, issuerN))
           (parseName (der, subjectN)) (raw (der, subjectN))
           (parseValidity (der, validN)) (raw (der, spkiN))
           (parseKeyAlg (der, spkiN)) sigValue exts
    end

  fun parsePem pem =
    let val blocks = Pem.decode pem
        val certs = List.filter (fn b => let val (label, _) = b in label = "CERTIFICATE" end) blocks
    in List.map (fn b => let val (_, d) = b in parse d end) certs end

  (* ===================== accessors ===================== *)

  fun cDer        (Cert x _ _ _ _ _ _ _ _ _ _ _ _ _ _) = x
  fun tbsCertificateDer (Cert _ x _ _ _ _ _ _ _ _ _ _ _ _ _) = x
  fun version     (Cert _ _ x _ _ _ _ _ _ _ _ _ _ _ _) = x
  fun cSerialCont (Cert _ _ _ x _ _ _ _ _ _ _ _ _ _ _) = x
  fun serialNumber(Cert _ _ _ _ x _ _ _ _ _ _ _ _ _ _) = x
  fun signatureAlg(Cert _ _ _ _ _ x _ _ _ _ _ _ _ _ _) = x
  fun issuer      (Cert _ _ _ _ _ _ x _ _ _ _ _ _ _ _) = x
  fun cIssuerDer  (Cert _ _ _ _ _ _ _ x _ _ _ _ _ _ _) = x
  fun subject     (Cert _ _ _ _ _ _ _ _ x _ _ _ _ _ _) = x
  fun cSubjectDer (Cert _ _ _ _ _ _ _ _ _ x _ _ _ _ _) = x
  fun validity    (Cert _ _ _ _ _ _ _ _ _ _ x _ _ _ _) = x
  fun subjectPublicKeyInfoDer (Cert _ _ _ _ _ _ _ _ _ _ _ x _ _ _) = x
  fun publicKeyAlg(Cert _ _ _ _ _ _ _ _ _ _ _ _ x _ _) = x
  fun signatureValue (Cert _ _ _ _ _ _ _ _ _ _ _ _ _ x _) = x
  fun extensions  (Cert _ _ _ _ _ _ _ _ _ _ _ _ _ _ x) = x

  fun notBefore c = let val (nb, _) = validity c in nb end
  fun notAfter  c = let val (_, na) = validity c in na end

  fun serialHex c =
    let val m = cSerialCont c
        val m2 = if String.size m > 1 andalso byteAt (m, 0) = 0
                 then String.extract m 1 None else m
    in toHexLower m2 end

  (* ===================== time ===================== *)

  fun compareTime (a, b) =
    let
      val Time ya moa da ha mia sa = a
      val Time yb mob db hb mib sb = b
      fun chain (ord, k) = case ord of Equal => k () | _ => ord
    in
      chain (Int.compare ya yb, fn () =>
      chain (Int.compare moa mob, fn () =>
      chain (Int.compare da db, fn () =>
      chain (Int.compare ha hb, fn () =>
      chain (Int.compare mia mib, fn () =>
             Int.compare sa sb)))))
    end

  fun pad2 n = (if n < 10 then "0" else "") ^ Int.toString n
  fun pad4 n = (if n < 1000 then "0" else "") ^ (if n < 100 then "0" else "")
               ^ (if n < 10 then "0" else "") ^ Int.toString n
  fun timeToString t =
    let val Time y mo da h mi s = t
    in pad4 y ^ "-" ^ pad2 mo ^ "-" ^ pad2 da ^ "T"
       ^ pad2 h ^ ":" ^ pad2 mi ^ ":" ^ pad2 s ^ "Z" end

  (* ===================== names ===================== *)

  fun commonName n =
    case List.find (fn a => let val (oid, _) = a in oid = oidCommonName end) n of
      Some a => let val (_, v) = a in Some v end
    | None => None

  fun shortOid oid =
    if oid = [2,5,4,3] then "CN"
    else if oid = [2,5,4,10] then "O"
    else if oid = [2,5,4,11] then "OU"
    else if oid = [2,5,4,6] then "C"
    else if oid = [2,5,4,7] then "L"
    else if oid = [2,5,4,8] then "ST"
    else if oid = [1,2,840,113549,1,9,1] then "emailAddress"
    else String.concatWith "." (List.map Int.toString oid)

  fun nameToString n =
    String.concatWith ","
      (List.map (fn a => let val (oid, value) = a in shortOid oid ^ "=" ^ value end)
                (List.rev n))

  (* ===================== extension-derived accessors ===================== *)

  fun findExtension c oid =
    List.find (fn e => let val (eo, _, _) = e in eo = oid end) (extensions c)

  fun rsaPublicKey c =
    case publicKeyAlg c of
      RsaKey => (Some (Rsa.decodeSpkiDer (subjectPublicKeyInfoDer c)) handle _ => None)
    | _ => None

  fun basicConstraints c =
    case findExtension c oidBasicConstr of
      None => None
    | Some e =>
        (let val (_, _, v) = e
             val seqN = readTLV (v, 0)
             val kids = children (v, seqN)
             val ca = case kids of
                        (b :: _) => if nTag b = 1 then boolOf (v, b) else False
                      | [] => False
             val pathLen =
               case List.find (fn k => nTag k = 2 andalso nCls k = 0) kids of
                 Some iN => Some (uintOf (v, iN))
               | None => None
         in Some (ca, pathLen) end) handle _ => None

  fun isCA c =
    case basicConstraints c of Some bc => let val (ca, _) = bc in ca end | None => False

  fun keyUsage c =
    case findExtension c oidKeyUsage of
      None => []
    | Some e =>
        (let
          val (_, _, v) = e
          val bsN = readTLV (v, 0)
          val bits = content (v, bsN)
          val names = [ "digitalSignature", "nonRepudiation", "keyEncipherment"
                      , "dataEncipherment", "keyAgreement", "keyCertSign"
                      , "cRLSign", "encipherOnly", "decipherOnly" ]
          fun bitSet i =
            let val byteIdx = 1 + (i div 8)
            in byteIdx < String.size bits
               andalso (byteAt (bits, byteIdx)
                        div (Word64.toInt (Word64.<< (0w1 : Word64.word) (7 - (i mod 8))))) mod 2 = 1
            end
          fun pick (i, xs) =
            case xs of
              [] => []
            | (nm :: rest) => (if bitSet i then [nm] else []) @ pick (i + 1, rest)
        in pick (0, names) end) handle _ => []

  fun extKeyUsage c =
    case findExtension c oidExtKeyUsage of
      None => []
    | Some e =>
        (let
          val (_, _, v) = e
          val seqN = readTLV (v, 0)
          fun nameOf oid =
            if oid = [1,3,6,1,5,5,7,3,1] then "serverAuth"
            else if oid = [1,3,6,1,5,5,7,3,2] then "clientAuth"
            else if oid = [1,3,6,1,5,5,7,3,3] then "codeSigning"
            else if oid = [1,3,6,1,5,5,7,3,4] then "emailProtection"
            else if oid = [1,3,6,1,5,5,7,3,8] then "timeStamping"
            else if oid = [1,3,6,1,5,5,7,3,9] then "OCSPSigning"
            else String.concatWith "." (List.map Int.toString oid)
        in List.map (fn k => nameOf (oidOf (v, k))) (children (v, seqN)) end) handle _ => []

  fun dnsNames c =
    case findExtension c oidSubjectAltName of
      None => []
    | Some e =>
        (let val (_, _, v) = e
             val seqN = readTLV (v, 0)
         in List.map (fn k => content (v, k))
              (List.filter (fn k => nCls k = 2 andalso nTag k = 2) (children (v, seqN)))
         end) handle _ => []

  fun subjectKeyId c =
    case findExtension c oidSubjectKeyId of
      None => None
    | Some e => let val (_, _, v) = e
                in (Some (content (v, readTLV (v, 0))) handle _ => None) end

  fun authorityKeyId c =
    case findExtension c oidAuthKeyId of
      None => None
    | Some e =>
        (let val (_, _, v) = e
             val seqN = readTLV (v, 0)
         in case List.find (fn k => nCls k = 2 andalso nTag k = 0) (children (v, seqN)) of
              Some k => Some (content (v, k))
            | None => None
         end) handle _ => None

  (* ===================== verification ===================== *)

  fun verifySignature (cert, issuer) =
    case rsaPublicKey issuer of
      None => Unsupported "issuer key is not RSA"
    | Some pub =>
        let
          val msg = tbsCertificateDer cert
          val sgn = signatureValue cert
          fun pkcs1 h = (if Rsa.verify (pub, h, msg, sgn) then Verified else Failed) handle _ => Failed
        in
          case signatureAlg cert of
            Sha1WithRsa   => pkcs1 Rsa.SHA1
          | Sha256WithRsa => pkcs1 Rsa.SHA256
          | Sha512WithRsa => pkcs1 Rsa.SHA512
          | Sha384WithRsa => Unsupported "SHA-384 not supported by sml-rsa"
          | RsaPss h sl =>
              ((if Rsa.verifyPss (pub, h, sl, msg, sgn) then Verified else Failed) handle _ => Failed)
          | EcdsaWithSha256 => Unsupported "ECDSA verification is out of scope"
          | EcdsaWithSha384 => Unsupported "ECDSA verification is out of scope"
          | EcdsaWithSha512 => Unsupported "ECDSA verification is out of scope"
          | Ed25519Sig      => Unsupported "Ed25519 verification is out of scope"
          | UnknownSigAlg _ => Unsupported "unknown signature algorithm"
        end

  fun verifySelfSigned c = verifySignature (c, c)

  (* ===================== path validation ===================== *)

  fun verifyChain (cert, intermediates, roots, time) =
    let
      fun timeOk c =
        let val (nb, na) = validity c
        in compareTime (nb, time) <> Greater andalso compareTime (time, na) <> Greater end

      fun isTrustedRoot c = List.exists (fn r => cDer r = cDer c) roots
      fun verOk (c, iss) = verifySignature (c, iss) = Verified

      fun loop (c, fuel) =
        if fuel <= 0 then ChainError "chain too long (possible loop)"
        else if not (timeOk c) then ChainError "certificate outside its validity window"
        else if cIssuerDer c = cSubjectDer c andalso isTrustedRoot c then
          (if verifySelfSigned c = Verified then ChainOk
           else ChainError "trusted root self-signature does not verify")
        else
          case List.find (fn r => cSubjectDer r = cIssuerDer c) roots of
            Some r =>
              if not (isCA r) then ChainError "issuer is not a CA"
              else if not (timeOk r) then ChainError "issuer outside its validity window"
              else if verOk (c, r) then ChainOk
              else ChainError "signature does not verify against trusted root"
          | None =>
              (case List.find (fn i => cSubjectDer i = cIssuerDer c) intermediates of
                 Some i =>
                   if not (isCA i) then ChainError "intermediate is not a CA"
                   else if not (verOk (c, i)) then
                     ChainError "signature does not verify against intermediate"
                   else loop (i, fuel - 1)
               | None => ChainError "no issuer certificate found")
    in
      loop (cert, List.length intermediates + List.length roots + 2)
    end

end
