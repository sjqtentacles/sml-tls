(* tls_state.sml -- CakeML port of TlsExtensions / TlsCertVerify /
   TlsClient / TlsServer / Tls (from extensions.sml, certverify.sml,
   tlsstate.sml).  Records -> tuples, words -> int, P256 stubbed. *)

structure TlsExtensions = struct
  fun word16ToBytes w =
    String.implode [Char.chr ((w div 256) mod 256), Char.chr (w mod 256)]
  fun bytesToWord16 (hi, lo) = hi * 256 + lo
  fun byteAt (s, i) =
    if i < 0 orelse i >= String.size s then None
    else Some (Char.ord (String.sub s i))
  fun readU16 (s, i) =
    case (byteAt (s, i), byteAt (s, i + 1)) of
        (Some hi, Some lo) => Some (bytesToWord16 (hi, lo), i + 2)
      | _ => None
  fun substringOpt (s, start, len) =
    if start < 0 orelse len < 0 orelse start + len > String.size s then None
    else Some (String.substring s start len)

  fun word32ToBytes w =
    String.implode
      [ Char.chr ((w div 16777216) mod 256), Char.chr ((w div 65536) mod 256)
      , Char.chr ((w div 256) mod 256), Char.chr (w mod 256) ]
  fun bytesToWord32 (a, b, c, d) = a * 16777216 + b * 65536 + c * 256 + d

  (* key_share: keyShareEntry = (group:int, keyExchange:string) *)
  fun encodeKeyShareCH xs =
    let
      fun one e =
        let val (group, keyExchange) = e in
          word16ToBytes group ^ word16ToBytes (String.size keyExchange) ^ keyExchange
        end
      val body = String.concat (List.map one xs)
    in word16ToBytes (String.size body) ^ body end

  fun decodeKeyShareCH s =
    let
      fun loop (i, end0, acc) =
        if i = end0 then Some (List.rev acc)
        else if i + 4 > end0 then None
        else
          case (byteAt (s, i), byteAt (s, i + 1)) of
              (Some hi, Some lo) =>
                let val group = bytesToWord16 (hi, lo) in
                  case readU16 (s, i + 2) of
                      None => None
                    | Some (klen, j) =>
                        if j + klen > end0 then None
                        else
                          case substringOpt (s, j, klen) of
                              None => None
                            | Some keyExchange =>
                                if klen = 0 then None
                                else loop (j + klen, end0, (group, keyExchange) :: acc)
                end
            | _ => None
    in
      case readU16 (s, 0) of
          None => None
        | Some (listLen, start) =>
            if start + listLen <> String.size s then None
            else if listLen = 0 then Some []
            else loop (start, start + listLen, [])
    end

  fun encodeKeyShareHRR group = word16ToBytes group

  fun decodeKeyShareHRR s =
    if String.size s <> 2 then None
    else case (byteAt (s, 0), byteAt (s, 1)) of
             (Some hi, Some lo) => Some (bytesToWord16 (hi, lo))
           | _ => None

  fun encodeKeyShareSH e =
    let val (group, keyExchange) = e in
      word16ToBytes group ^ word16ToBytes (String.size keyExchange) ^ keyExchange
    end

  fun decodeKeyShareSH s =
    if String.size s < 4 then None
    else
      case (byteAt (s, 0), byteAt (s, 1)) of
          (Some hi, Some lo) =>
            let val group = bytesToWord16 (hi, lo) in
              case readU16 (s, 2) of
                  None => None
                | Some (klen, keyStart) =>
                    if klen = 0 then None
                    else if keyStart + klen <> String.size s then None
                    else case substringOpt (s, keyStart, klen) of
                             None => None
                           | Some keyExchange => Some (group, keyExchange)
            end
        | _ => None

  (* supported_versions *)
  fun encodeSupportedVersionsCH vs =
    let
      val body = String.concat (List.map word16ToBytes vs)
      val n = String.size body
    in
      if n > 255 then raise (Fail "supported_versions: too many")
      else String.str (Char.chr n) ^ body
    end

  fun decodeSelectedVersionSH s =
    if String.size s <> 2 then None
    else case (byteAt (s, 0), byteAt (s, 1)) of
             (Some hi, Some lo) => Some (bytesToWord16 (hi, lo))
           | _ => None

  (* supported_groups *)
  fun encodeSupportedGroups vs =
    let val body = String.concat (List.map word16ToBytes vs)
    in word16ToBytes (String.size body) ^ body end

  fun decodeWord16List s =
    case readU16 (s, 0) of
        None => None
      | Some (listLen, start) =>
          if start + listLen <> String.size s then None
          else if listLen mod 2 <> 0 then None
          else
            let
              fun loop (i, end0, acc) =
                if i = end0 then Some (List.rev acc)
                else case (byteAt (s, i), byteAt (s, i + 1)) of
                         (Some hi, Some lo) =>
                           loop (i + 2, end0, bytesToWord16 (hi, lo) :: acc)
                       | _ => None
            in loop (start, start + listLen, []) end

  fun decodeSupportedGroups s = decodeWord16List s

  (* signature_algorithms *)
  fun encodeSignatureAlgorithms vs =
    let val body = String.concat (List.map word16ToBytes vs)
    in word16ToBytes (String.size body) ^ body end

  fun decodeSignatureAlgorithms s = decodeWord16List s

  (* server_name (host_name) *)
  fun encodeServerName name =
    let
      val nameLen = String.size name
      val entry = String.str (Char.chr 0) ^ word16ToBytes nameLen ^ name
      val listLen = String.size entry
    in word16ToBytes listLen ^ entry end

  fun decodeServerName s =
    case readU16 (s, 0) of
        None => None
      | Some (listLen, start) =>
          if start + listLen <> String.size s then None
          else if listLen = 0 then None
          else
            case byteAt (s, start) of
                None => None
              | Some nameType =>
                  if nameType <> 0 then None
                  else
                    case readU16 (s, start + 1) of
                        None => None
                      | Some (nameLen, nameStart) =>
                          if nameStart + nameLen <> start + listLen then None
                          else substringOpt (s, nameStart, nameLen)

  (* ALPN *)
  fun encodeAlpn xs =
    let
      fun one p =
        let val n = String.size p in
          if n > 255 then raise (Fail "alpn: protocol too long")
          else String.str (Char.chr n) ^ p
        end
      val body = String.concat (List.map one xs)
    in word16ToBytes (String.size body) ^ body end

  fun decodeAlpn s =
    case readU16 (s, 0) of
        None => None
      | Some (listLen, start) =>
          if start + listLen <> String.size s then None
          else
            let
              fun loop (i, end0, acc) =
                if i = end0 then Some (List.rev acc)
                else case byteAt (s, i) of
                         None => None
                       | Some plen =>
                           if plen = 0 then None
                           else if i + 1 + plen > end0 then None
                           else case substringOpt (s, i + 1, plen) of
                                    None => None
                                  | Some p => loop (i + 1 + plen, end0, p :: acc)
            in loop (start, start + listLen, []) end

  (* cookie *)
  fun encodeCookie cookie = word16ToBytes (String.size cookie) ^ cookie

  fun decodeCookie s =
    case readU16 (s, 0) of
        None => None
      | Some (n, start) =>
          if n = 0 then None
          else if start + n <> String.size s then None
          else substringOpt (s, start, n)

  (* psk_key_exchange_modes (modes are ints) *)
  val pskModeKe = 0
  val pskModeDheKe = 1

  fun encodePskKeyExchangeModes modes =
    let val body = String.implode (List.map Char.chr modes) in
      String.str (Char.chr (String.size body)) ^ body
    end

  fun decodePskKeyExchangeModes s =
    case byteAt (s, 0) of
        None => None
      | Some n =>
          if n = 0 then None
          else if 1 + n <> String.size s then None
          else
            let
              fun loop (i, acc) =
                if i = 1 + n then Some (List.rev acc)
                else case byteAt (s, i) of
                         None => None
                       | Some b => loop (i + 1, b :: acc)
            in loop (1, []) end

  (* early_data *)
  val encodeEarlyDataEmpty = ""
  fun encodeEarlyDataMaxSize w = word32ToBytes w
  fun decodeEarlyDataMaxSize s =
    if String.size s <> 4 then None
    else case (byteAt (s, 0), byteAt (s, 1), byteAt (s, 2), byteAt (s, 3)) of
             (Some a, Some b, Some c, Some d) => Some (bytesToWord32 (a, b, c, d))
           | _ => None

  (* pre_shared_key: pskIdentity = (identity:string, age:int) *)
  fun encodeOfferedPsksIdentities ids =
    let
      fun one e =
        let val (identity, age) = e in
          word16ToBytes (String.size identity) ^ identity ^ word32ToBytes age
        end
      val body = String.concat (List.map one ids)
    in word16ToBytes (String.size body) ^ body end

  fun binderListLength binders =
    List.foldl (fn b => fn n => n + 1 + String.size b) 0 binders

  fun encodeBinderList binders =
    let
      val body = String.concat
        (List.map (fn b => String.str (Char.chr (String.size b)) ^ b) binders)
    in word16ToBytes (String.size body) ^ body end

  fun encodeSelectedIdentity idx = word16ToBytes idx

  fun decodeSelectedIdentity s =
    if String.size s <> 2 then None
    else case (byteAt (s, 0), byteAt (s, 1)) of
             (Some hi, Some lo) => Some (bytesToWord16 (hi, lo))
           | _ => None

  (* negotiation helpers *)
  val tls13 = 0x0304

  fun negotiateVersion clientVersions =
    case List.find (fn v => v = tls13) clientVersions of
        Some _ => Some tls13
      | None => None

  fun negotiateGroup (clientShares, serverGroups) =
    let
      fun member (g, gs) = List.exists (fn g2 => g2 = g) gs
      fun loop xs =
        case xs of
            [] => None
          | (e :: rest) =>
              let val (g, _) = e in
                if member (g, serverGroups) then Some g else loop rest
              end
    in loop clientShares end

  fun negotiateSigAlg (client, server) =
    let
      fun member (g, gs) = List.exists (fn g2 => g2 = g) gs
      fun loop xs =
        case xs of
            [] => None
          | (x :: rest) => if member (x, server) then Some x else loop rest
    in loop client end

  (* downgrade sentinels *)
  val downgradeSentinelTls12 =
    String.implode (List.map Char.chr
      [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01])
  val downgradeSentinelTls11 =
    String.implode (List.map Char.chr
      [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00])
end

structure TlsCertVerify = struct
  datatype result = Valid | Invalid TlsAlert.alertDescription

  fun listNull xs = case xs of [] => True | _ => False

  fun listMapPartial f xs =
    case xs of
        [] => []
      | (x :: rest) =>
          (case f x of
               Some v => v :: listMapPartial f rest
             | None => listMapPartial f rest)

  fun listEq (xs, ys) =
    case (xs, ys) of
        ([], []) => True
      | (a :: xs1, b :: ys1) => a = b andalso listEq (xs1, ys1)
      | _ => False

  (* unix seconds -> X509.time (Howard Hinnant civil-from-days) *)
  fun unixToTime unix =
    let
      val days0 = unix div 86400
      val secsOfDay0 = unix mod 86400
      val secsOfDay = if secsOfDay0 < 0 then secsOfDay0 + 86400 else secsOfDay0
      val days = if unix < 0 then days0 - 1 else days0
      val z = days + 719468
      val era = if z >= 0 then z div 146097 else (z - 146096) div 146097
      val doe = z - era * 146097
      val yoe = (doe - doe div 1460 + doe div 36524 - doe div 146096) div 365
      val y0 = yoe + era * 400
      val doy = doe - (365 * yoe + yoe div 4 - yoe div 100)
      val mp = (5 * doy + 2) div 153
      val d = doy - (153 * mp + 2) div 5 + 1
      val m = if mp < 10 then mp + 3 else mp - 9
      val y = if m <= 2 then y0 + 1 else y0
      val hour = secsOfDay div 3600
      val minute = (secsOfDay div 60) mod 60
      val second = secsOfDay mod 60
    in X509.Time y m d hour minute second end

  fun toLower c =
    if Char.>= c #"A" andalso Char.<= c #"Z" then
      Char.chr (Char.ord c + (Char.ord #"a" - Char.ord #"A"))
    else c

  fun lower s = String.implode (List.map toLower (String.explode s))

  fun splitDots s =
    let
      fun loop (acc, start, i) =
        if i >= String.size s then
          List.rev (String.substring s start (i - start) :: acc)
        else if Char.= (String.sub s i) #"." then
          loop (String.substring s start (i - start) :: acc, i + 1, i + 1)
        else loop (acc, start, i + 1)
    in if s = "" then [] else loop ([], 0, 0) end

  fun matchHostname (host, certName) =
    let
      val hLabels = splitDots (lower host)
      val nLabels = splitDots (lower certName)
    in
      case nLabels of
          [] => False
        | (first :: rest) =>
            if first = "*" then
              (case hLabels of
                   [] => False
                 | (hFirst :: hRest) =>
                     hFirst <> ""
                     andalso List.length hRest = List.length rest
                     andalso listEq (hRest, rest))
            else
              List.length hLabels = List.length nLabels
              andalso listEq (hLabels, nLabels)
    end

  (* signature schemes (ints) *)
  val schemeRsaPkcs1Sha256 = 0x0804
  val schemeRsaPkcs1Sha384 = 0x0805
  val schemeRsaPkcs1Sha512 = 0x0806
  val schemeRsaPssSha256 = 0x0809
  val schemeRsaPssSha384 = 0x080a
  val schemeRsaPssSha512 = 0x080b
  val schemeEcdsaSha256 = 0x0403
  val schemeEcdsaSha384 = 0x0503
  val schemeEcdsaSha512 = 0x0603

  fun sigAlgAcceptable (sigAlg, sigAlgs) =
    let fun member x = List.exists (fn y => y = x) sigAlgs in
      case sigAlg of
          X509.Sha256WithRsa => Some (member schemeRsaPkcs1Sha256)
        | X509.Sha384WithRsa => Some (member schemeRsaPkcs1Sha384)
        | X509.Sha512WithRsa => Some (member schemeRsaPkcs1Sha512)
        | X509.RsaPss h sl =>
            (case h of
                 Rsa.SHA256 => Some (member schemeRsaPssSha256)
               | Rsa.SHA512 => Some (member schemeRsaPssSha512)
               | Rsa.SHA1 => None)
        | X509.Sha1WithRsa => None
        | X509.EcdsaWithSha256 => Some (member schemeEcdsaSha256)
        | X509.EcdsaWithSha384 => Some (member schemeEcdsaSha384)
        | X509.EcdsaWithSha512 => Some (member schemeEcdsaSha512)
        | X509.Ed25519Sig => None
        | X509.UnknownSigAlg _ => None
    end

  fun parseOcspStatus stapled =
    if String.size stapled = 0 then None else Some stapled

  fun tryParse der = Some (X509.parse der) handle X509.X509 _ => None

  fun validityOk (c, nowTime) =
    let val (notBefore, notAfter) = X509.validity c in
      X509.compareTime (notBefore, nowTime) <> Greater
      andalso X509.compareTime (nowTime, notAfter) <> Greater
    end

  fun issuerMatches (child, candidate) =
    X509.nameToString (X509.subject candidate) =
    X509.nameToString (X509.issuer child)

  fun sameCert (a, b) =
    X509.subject a = X509.subject b
    andalso X509.issuer a = X509.issuer b
    andalso X509.serialNumber a = X509.serialNumber b

  fun isTrustAnchor (c, trust) =
    List.exists
      (fn tDer => case tryParse tDer of Some t => sameCert (c, t) | None => False)
      trust

  fun leafGate (hostOk, ekuOk, leafSigOk) =
    if not leafSigOk then Invalid TlsAlert.BadCertificate
    else if not ekuOk then Invalid TlsAlert.BadCertificate
    else if not hostOk then Invalid TlsAlert.UnrecognizedName
    else Valid

  fun verifyChain (chain, trust, hostname, now, sigAlgs) =
    case chain of
        [] => Invalid TlsAlert.BadCertificate
      | (leafDer :: restDers) =>
          (case tryParse leafDer of
               None => Invalid TlsAlert.BadCertificate
             | Some leaf =>
                 let
                   val restCerts = listMapPartial tryParse restDers
                   val nowTime = unixToTime now
                   val sanNames = X509.dnsNames leaf
                   val cnNames =
                     case X509.commonName (X509.subject leaf) of
                         Some cn => [cn]
                       | None => []
                   val namesToCheck = if listNull sanNames then cnNames else sanNames
                   val hostOk =
                     List.exists (fn nm => matchHostname (hostname, nm)) namesToCheck
                   val ekus = X509.extKeyUsage leaf
                   val ekuOk =
                     listNull ekus orelse
                     List.exists (fn p => p = "serverAuth") ekus
                   val leafSigOk =
                     case sigAlgAcceptable (X509.signatureAlg leaf, sigAlgs) of
                         Some True => True
                       | Some False => False
                       | None => False
                   fun loop (cur, remaining, fuel, isLeaf, intermediatesBelow) =
                     if fuel <= 0 then Invalid TlsAlert.UnknownCa
                     else if not (validityOk (cur, nowTime)) then
                       Invalid TlsAlert.CertificateExpired
                     else
                       let
                         val curPathLen =
                           case X509.basicConstraints cur of
                               Some (_, Some k) => Some k
                             | _ => None
                         val pathLenOk =
                           case curPathLen of
                               Some k => intermediatesBelow <= k
                             | None => True
                       in
                         if not pathLenOk then Invalid TlsAlert.BadCertificate
                         else if isTrustAnchor (cur, trust) then
                           (case X509.verifySelfSigned cur of
                                X509.Verified => leafGate (hostOk, ekuOk, leafSigOk)
                              | X509.Failed => Invalid TlsAlert.UnknownCa
                              | X509.Unsupported _ =>
                                  Invalid TlsAlert.UnsupportedCertificate)
                         else
                           let
                             val interIssuer =
                               List.find (fn c => issuerMatches (cur, c)) remaining
                             val trustIssuer =
                               case interIssuer of
                                   Some _ => None
                                 | None =>
                                     List.find
                                       (fn tDer =>
                                          case tryParse tDer of
                                              Some t => issuerMatches (cur, t)
                                            | None => False)
                                       trust
                           in
                             case (interIssuer, trustIssuer) of
                                 (Some iss, _) =>
                                   let
                                     val ca = X509.isCA iss
                                     val ku = X509.keyUsage iss
                                     val hasKeyCertSign =
                                       listNull ku orelse
                                       List.exists (fn k => k = "keyCertSign") ku
                                     val newIntermediatesBelow =
                                       if (not isLeaf) andalso X509.isCA cur
                                          andalso
                                          X509.nameToString (X509.subject cur)
                                            <> X509.nameToString (X509.issuer cur)
                                       then intermediatesBelow + 1
                                       else intermediatesBelow
                                   in
                                     if not ca then Invalid TlsAlert.UnknownCa
                                     else if not hasKeyCertSign then
                                       Invalid TlsAlert.BadCertificate
                                     else if not (validityOk (iss, nowTime)) then
                                       Invalid TlsAlert.CertificateExpired
                                     else
                                       (case X509.verifySignature (cur, iss) of
                                            X509.Verified =>
                                              loop
                                                (iss,
                                                 List.filter
                                                   (fn c => not (issuerMatches (cur, c)))
                                                   remaining,
                                                 fuel - 1, False,
                                                 newIntermediatesBelow)
                                          | X509.Failed => Invalid TlsAlert.DecryptError
                                          | X509.Unsupported _ =>
                                              Invalid TlsAlert.UnsupportedCertificate)
                                   end
                               | (None, Some tDer) =>
                                   (case tryParse tDer of
                                        Some iss =>
                                          let
                                            val ca = X509.isCA iss
                                            val ku = X509.keyUsage iss
                                            val hasKeyCertSign =
                                              listNull ku orelse
                                              List.exists (fn k => k = "keyCertSign") ku
                                          in
                                            if not ca then Invalid TlsAlert.UnknownCa
                                            else if not hasKeyCertSign then
                                              Invalid TlsAlert.BadCertificate
                                            else if not (validityOk (iss, nowTime)) then
                                              Invalid TlsAlert.CertificateExpired
                                            else
                                              (case X509.verifySignature (cur, iss) of
                                                   X509.Verified =>
                                                     leafGate (hostOk, ekuOk, leafSigOk)
                                                 | X509.Failed =>
                                                     Invalid TlsAlert.DecryptError
                                                 | X509.Unsupported _ =>
                                                     Invalid TlsAlert.UnsupportedCertificate)
                                          end
                                      | None => Invalid TlsAlert.UnknownCa)
                               | (None, None) => Invalid TlsAlert.UnknownCa
                           end
                       end
                 in
                   loop (leaf, restCerts, List.length chain + 2, True, 0)
                 end)
end

(* clientConfig = (x25519Priv, p256Priv, clientRandom, legacySessionId,
     cipherSuites, extensions, serverName, trustStore, now, sigAlgs)
   clientState  = (config, x25519Priv, clientHello, transcript, cipherSuite,
     dhe, clientHsSecret, serverHsSecret, clientHandshakeKey, serverAppKey,
     clientAppKey, serverHsProtect, certVerified, errorAlert, connected) *)
structure TlsClient = struct
  exception Tls string
  exception Fatal TlsAlert.alertDescription

  fun optValOf x = case x of Some v => v | None => raise (Tls "valOf None")

  val maxCiphertextLen = 16384 + 256

  fun suiteAlg cs =
    if cs = TlsHandshake.suiteTlsAes128GcmSha256 then Aead.AAesGcm128
    else if cs = TlsHandshake.suiteTlsAes256GcmSha384 then Aead.AAesGcm256
    else if cs = TlsHandshake.suiteTlsChaCha20Poly1305 then Aead.AChaCha20Poly1305
    else Aead.AAesGcm128

  fun suiteKeyIvLen cs =
    if cs = TlsHandshake.suiteTlsAes256GcmSha384 then (32, 12) else (16, 12)

  fun mkProtect (cs, kv) =
    let val (key, iv) = kv in TlsRecordProtect.initWithAlg (key, iv, suiteAlg cs) end

  fun findExt (exts, ty) =
    case List.find (fn e => let val (et, _) = e in et = ty end) exts of
        Some e => let val (_, d) = e in Some d end
      | None => None

  (* clientHello accessors (6-tuple) *)
  fun chCipherSuites ch = let val (_, _, _, a, _, _) = ch in a end
  fun chExtensions ch = let val (_, _, _, _, _, a) = ch in a end
  (* serverHello accessors (6-tuple) *)
  fun shLegacyVersion sh = let val (a, _, _, _, _, _) = sh in a end
  fun shRandom sh = let val (_, a, _, _, _, _) = sh in a end
  fun shCipherSuite sh = let val (_, _, _, a, _, _) = sh in a end
  fun shLegacyCompression sh = let val (_, _, _, _, a, _) = sh in a end
  fun shExtensions sh = let val (_, _, _, _, _, a) = sh in a end

  fun buildClientHello (cfg, keyShareGroup, cookieOpt) =
    let
      val (cfgX25519, cfgP256, cfgRandom, cfgSessionId, cfgCS, cfgExts,
           cfgSN, cfgTrust, cfgNow, cfgSigAlgs) = cfg
      val pub = X25519.base cfgX25519
      val keyShare = (TlsHandshake.extKeyShare,
                      TlsExtensions.encodeKeyShareCH [(TlsHandshake.groupX25519, pub)])
      val supVer = (TlsHandshake.extSupportedVersions,
                    String.str (Char.chr 2) ^ TlsHandshake.word16ToBytes 0x0304)
      val supGrp = (TlsHandshake.extSupportedGroups,
                    TlsExtensions.encodeSupportedGroups [TlsHandshake.groupX25519])
      val sigAlg = (TlsHandshake.extSignatureAlgorithms,
                    TlsExtensions.encodeSignatureAlgorithms
                      [TlsHandshake.sigRsaPssRsaSha256, TlsHandshake.sigRsaPssRsaSha384,
                       TlsHandshake.sigRsaPssRsaSha512])
      val sni = if cfgSN = "" then []
                else [(TlsHandshake.extServerName, TlsExtensions.encodeServerName cfgSN)]
      val cookie = case cookieOpt of
                       Some c => [(TlsHandshake.extCookie, TlsExtensions.encodeCookie c)]
                     | None => []
      val allExts = List.concat [cfgExts, [keyShare, supVer, supGrp, sigAlg], sni, cookie]
    in (0x0303, cfgRandom, cfgSessionId, cfgCS, [0], allExts) end

  fun startHandshake cfg =
    let
      val (cfgX25519, _, _, _, _, _, _, _, _, _) = cfg
      val ch = buildClientHello (cfg, TlsHandshake.groupX25519, None)
      val body = TlsHandshake.encodeClientHello ch
      val msg = TlsHandshake.encodeMessage (TlsHandshake.ClientHello, body)
      val record = TlsRecord.encodePlaintext (TlsRecord.Handshake, msg)
      val st = (cfg, cfgX25519, ch, msg, None, "", None, None, None, None, None,
                None, False, None, False)
    in (st, record) end

  fun processServerHello (st, shBody) =
    case TlsHandshake.decodeServerHello shBody of
        None => raise (Fatal TlsAlert.DecodeError)
      | Some sh =>
          let
            val (config, priv, clientHello, transcript, _, _, _, _, _, _, _,
                 _, certVerified, _, _) = st
            val _ = if shLegacyVersion sh = 0x0303 then ()
                    else raise (Fatal TlsAlert.IllegalParameter)
            val _ = if shLegacyCompression sh = 0 then ()
                    else raise (Fatal TlsAlert.IllegalParameter)
            val cs = shCipherSuite sh
            val _ = if List.exists (fn c => c = cs) (chCipherSuites clientHello) then ()
                    else raise (Fatal TlsAlert.IllegalParameter)
            val rnd = shRandom sh
            val _ = if String.size rnd >= 8 then
                      let val tail = String.substring rnd (String.size rnd - 8) 8 in
                        if tail = TlsExtensions.downgradeSentinelTls12 orelse
                           tail = TlsExtensions.downgradeSentinelTls11
                        then raise (Fatal TlsAlert.IllegalParameter) else ()
                      end
                    else ()
            val _ = case findExt (shExtensions sh, TlsHandshake.extSupportedVersions) of
                        Some data =>
                          (case TlsExtensions.decodeSelectedVersionSH data of
                               Some v => if v = 0x0304 then ()
                                         else raise (Fatal TlsAlert.ProtocolVersion)
                             | None => raise (Fatal TlsAlert.DecodeError))
                      | None => raise (Fatal TlsAlert.MissingExtension)
            val (group, peerPub) =
              case (case findExt (shExtensions sh, TlsHandshake.extKeyShare) of
                        None => None
                      | Some data => TlsExtensions.decodeKeyShareSH data) of
                  None => raise (Fatal TlsAlert.MissingExtension)
                | Some ge =>
                    let val (g, kx) = ge in
                      if g = TlsHandshake.groupX25519 then (g, kx)
                      else raise (Fatal TlsAlert.IllegalParameter)
                    end
            val dhe = if group = TlsHandshake.groupX25519 andalso String.size peerPub = 32
                      then X25519.dh priv peerPub
                      else raise (Fatal TlsAlert.IllegalParameter)
            val shMsg = TlsHandshake.encodeMessage (TlsHandshake.ServerHello, shBody)
            val transcript2 = transcript ^ shMsg
            val (es, hs, ms, cHs, sHs, cAp, sAp) =
              TlsKeySchedule.schedule (dhe, transcript2, "")
            val (keyLen, ivLen) = suiteKeyIvLen cs
            val sHsKey = TlsKeySchedule.trafficKey (sHs, keyLen)
            val sHsIv = TlsKeySchedule.trafficIv (sHs, ivLen)
            val cHsKey = TlsKeySchedule.trafficKey (cHs, keyLen)
            val cHsIv = TlsKeySchedule.trafficIv (cHs, ivLen)
          in
            (config, priv, clientHello, transcript2, Some cs, dhe, Some cHs, Some sHs,
             Some (cHsKey, cHsIv), None, None, Some (mkProtect (cs, (sHsKey, sHsIv))),
             certVerified, None, False)
          end

  fun alertRecord desc =
    TlsRecord.encodePlaintext
      (TlsRecord.Alert, TlsAlert.encode (TlsAlert.Fatal, desc))

  fun setError (st, desc) =
    let val (config, priv, ch, tr, cs, dhe, cHsS, sHsS, cHsK, sApK, cApK,
             sHsP, certV, _, conn) = st in
      (config, priv, ch, tr, cs, dhe, cHsS, sHsS, cHsK, sApK, cApK, sHsP, certV,
       Some (TlsAlert.alertDescriptionToByte desc), conn)
    end

  fun verifyServerCert (config, certBody) =
    let val (_, _, _, _, _, _, cfgSN, cfgTrust, cfgNow, cfgSigAlgs) = config in
      case cfgTrust of
          [] => ()
        | _ =>
            (case TlsHandshake.decodeCertificate certBody of
                 None => raise (Fatal TlsAlert.DecodeError)
               | Some (_, certificateList) =>
                   let
                     val chain = List.map (fn e => let val (cd, _) = e in cd end)
                                          certificateList
                     val result =
                       TlsCertVerify.verifyChain (chain, cfgTrust, cfgSN, cfgNow, cfgSigAlgs)
                       handle _ => TlsCertVerify.Invalid TlsAlert.BadCertificate
                   in
                     case result of
                         TlsCertVerify.Valid => ()
                       | TlsCertVerify.Invalid desc => raise (Fatal desc)
                   end)
    end

  fun decryptFlight (remaining, prot, acc) =
    if remaining = "" then (prot, acc)
    else
      case TlsRecord.decodeCiphertext remaining of
          None => raise (Fatal TlsAlert.DecodeError)
        | Some (crec, rest) =>
            let val (ct, enc) = crec in
              if ct = TlsRecord.ChangeCipherSpec then decryptFlight (rest, prot, acc)
              else if String.size enc > maxCiphertextLen then
                raise (Fatal TlsAlert.RecordOverflow)
              else
                case TlsRecordProtect.unprotect (prot, enc) of
                    None => raise (Fatal TlsAlert.BadRecordMac)
                  | Some (it, pt, prot2) => decryptFlight (rest, prot2, acc ^ pt)
            end

  fun processFlight (st, hsBytes) =
    let
      val (config, priv, clientHello, trSH, cipherSuiteOpt, dhe, cHsSecOpt,
           sHsSecOpt, cHsKeyOpt, _, _, sHsProtOpt, certVerified0, _, _) = st
      val cs = optValOf cipherSuiteOpt
      val serverHsSecret = optValOf sHsSecOpt
      val clientHsSecret = optValOf cHsSecOpt
      val (keyLen, ivLen) = suiteKeyIvLen cs
      val (cfgX25519, cfgP256, cfgRandom, cfgSessionId, cfgCS, cfgExts,
           cfgSN, cfgTrust, cfgNow, cfgSigAlgs) = config
      fun loop (remaining, transcript, certOk, leafCert) =
        if remaining = "" then
          ((config, priv, clientHello, transcript, cipherSuiteOpt, dhe, cHsSecOpt,
            sHsSecOpt, cHsKeyOpt, None, None, sHsProtOpt, certOk, None, False), [])
        else
          case TlsHandshake.decodeMessage remaining of
              None => raise (Fatal TlsAlert.DecodeError)
            | Some (mtb, rest) =>
                let
                  val (msgType, body) = mtb
                  val msg = TlsHandshake.encodeMessage (msgType, body)
                  val transcript2 = transcript ^ msg
                in
                  case msgType of
                      TlsHandshake.Certificate =>
                        let
                          val leaf =
                            case TlsHandshake.decodeCertificate body of
                                Some (_, (e :: _)) => let val (cd, _) = e in Some cd end
                              | _ => None
                          val _ = verifyServerCert (config, body)
                        in loop (rest, transcript2, True, leaf) end
                    | TlsHandshake.CertificateVerify =>
                        (case TlsHandshake.decodeCertificateVerify body of
                             None => raise (Fatal TlsAlert.DecodeError)
                           | Some (sigAlg, sigBytes) =>
                               if sigBytes = "" then loop (rest, transcript2, certOk, leafCert)
                               else
                                 let
                                   val _ = if List.exists (fn a => a = sigAlg) cfgSigAlgs
                                           then () else raise (Fatal TlsAlert.IllegalParameter)
                                   val pub =
                                     case leafCert of
                                         None => raise (Fatal TlsAlert.DecryptError)
                                       | Some der =>
                                           (case (X509.rsaPublicKey (X509.parse der)
                                                  handle _ => None) of
                                                Some p => p
                                              | None => raise (Fatal TlsAlert.BadCertificate))
                                   val ok = TlsKeySchedule.verifyServerCertVerify
                                              (pub, sigAlg, transcript, sigBytes)
                                   val _ = if ok then () else raise (Fatal TlsAlert.DecryptError)
                                 in loop (rest, transcript2, True, leafCert) end)
                    | TlsHandshake.Finished =>
                        let
                          val sfKey = TlsKeySchedule.finishedKey serverHsSecret
                          val expected = TlsKeySchedule.finishedVerifyData (sfKey, transcript)
                          val _ = if expected = body then ()
                                  else raise (Fatal TlsAlert.DecryptError)
                          val (es, hs2, ms, cHs2, sHs2, cAp, sAp) =
                            TlsKeySchedule.schedule (dhe, trSH, transcript2)
                          val sApKey = TlsKeySchedule.trafficKey (sAp, keyLen)
                          val sApIv = TlsKeySchedule.trafficIv (sAp, ivLen)
                          val cApKey = TlsKeySchedule.trafficKey (cAp, keyLen)
                          val cApIv = TlsKeySchedule.trafficIv (cAp, ivLen)
                          val cfKey = TlsKeySchedule.finishedKey clientHsSecret
                          val cfVerify = TlsKeySchedule.finishedVerifyData (cfKey, transcript2)
                          val cfBody = TlsHandshake.encodeFinished cfVerify
                          val cfMsg = TlsHandshake.encodeMessage (TlsHandshake.Finished, cfBody)
                          val cfProt = mkProtect (cs, optValOf cHsKeyOpt)
                          val (cfRecBody, _) =
                            TlsRecordProtect.protect (cfProt, TlsRecord.Handshake, cfMsg, 0)
                          val cfRecord =
                            TlsRecord.encodeCiphertext (TlsRecord.ApplicationData, cfRecBody)
                          val st2 = (config, priv, clientHello, transcript2 ^ cfMsg,
                                     cipherSuiteOpt, dhe, cHsSecOpt, sHsSecOpt, cHsKeyOpt,
                                     Some (sApKey, sApIv), Some (cApKey, cApIv), sHsProtOpt,
                                     certOk, None, True)
                        in (st2, [cfRecord]) end
                    | _ => loop (rest, transcript2, certOk, leafCert)
                end
    in loop (hsBytes, trSH, certVerified0, None) end

  fun step (st, input) =
    (let
       val (config, priv, ch, tr, cipherSuiteOpt, dhe, cHsS, sHsS, cHsK, sApK,
            cApK, sHsP, certV, errA, conn) = st
     in
       case errA of
           Some _ => (st, [])
         | None =>
             (case cipherSuiteOpt of
                  None =>
                    let
                      val (body, rest) =
                        case TlsRecord.decodePlaintext input of
                            Some (r, rest) =>
                              let val (ct, frag) = r in
                                if ct = TlsRecord.Handshake then (frag, rest)
                                else (input, "")
                              end
                          | None => (input, "")
                    in
                      case TlsHandshake.decodeMessage body of
                          Some (mtb, _) =>
                            let val (mt, shBody) = mtb in
                              case mt of
                                  TlsHandshake.ServerHello =>
                                    (case TlsHandshake.decodeServerHello shBody of
                                         None => raise (Fatal TlsAlert.DecodeError)
                                       | Some sh =>
                                           if shRandom sh = TlsHandshake.helloRetryRequestRandom
                                           then raise (Fatal TlsAlert.IllegalParameter)
                                           else
                                             let val st2 = processServerHello (st, shBody) in
                                               if rest = "" then (st2, []) else step (st2, rest)
                                             end)
                                | _ => raise (Fatal TlsAlert.UnexpectedMessage)
                            end
                        | None => raise (Fatal TlsAlert.UnexpectedMessage)
                    end
                | Some _ =>
                    if not conn then
                      let
                        val prot0 = optValOf sHsP
                        val (_, hs) = decryptFlight (input, prot0, "")
                      in processFlight (st, hs) end
                    else (st, []))
     end)
    handle Fatal desc => (setError (st, desc), [alertRecord desc])
         | _ => (setError (st, TlsAlert.DecodeError), [alertRecord TlsAlert.DecodeError])

  fun negotiatedCipherSuite st =
    let val (_, _, _, _, cs, _, _, _, _, _, _, _, _, _, _) = st in cs end
  fun serverAppKey st =
    let val (_, _, _, _, _, _, _, _, _, k, _, _, _, _, _) = st in k end
  fun clientAppKey st =
    let val (_, _, _, _, _, _, _, _, _, _, k, _, _, _, _) = st in k end
  fun isConnected st =
    let val (_, _, _, _, _, _, _, _, _, _, _, _, _, _, c) = st in c end
  fun certVerified st =
    let val (_, _, _, _, _, _, _, _, _, _, _, _, cv, _, _) = st in cv end
  fun error st =
    let val (_, _, _, _, _, _, _, _, _, _, _, _, _, e, _) = st in e end
  fun transcript st =
    let val (_, _, _, t, _, _, _, _, _, _, _, _, _, _, _) = st in t end
end

(* serverConfig = (x25519Priv, p256Priv, serverRandom, cipherSuite,
     legacySessionId, extensions, certChain, rsaPrivateKeyDer, sigAlg, now, sigAlgs)
   serverState  = (cipherSuite, transcript, dhe, clientHello, clientHsSecret,
     serverHsSecret, serverHandshakeKey, serverAppKey, clientAppKey,
     clientHsProtect, errorAlert, connected) *)
structure TlsServer = struct
  exception Tls string
  exception Fatal TlsAlert.alertDescription

  fun optValOf x = case x of Some v => v | None => raise (Tls "valOf None")

  val maxCiphertextLen = 16384 + 256

  fun suiteAlg cs =
    if cs = TlsHandshake.suiteTlsAes128GcmSha256 then Aead.AAesGcm128
    else if cs = TlsHandshake.suiteTlsAes256GcmSha384 then Aead.AAesGcm256
    else if cs = TlsHandshake.suiteTlsChaCha20Poly1305 then Aead.AChaCha20Poly1305
    else Aead.AAesGcm128

  fun suiteKeyIvLen cs =
    if cs = TlsHandshake.suiteTlsAes256GcmSha384 then (32, 12) else (16, 12)

  fun mkProtect (cs, kv) =
    let val (key, iv) = kv in TlsRecordProtect.initWithAlg (key, iv, suiteAlg cs) end

  fun alertRecord desc =
    TlsRecord.encodePlaintext
      (TlsRecord.Alert, TlsAlert.encode (TlsAlert.Fatal, desc))

  fun findExt (exts, ty) =
    case List.find (fn e => let val (et, _) = e in et = ty end) exts of
        Some e => let val (_, d) = e in Some d end
      | None => None

  fun chExtensions ch = let val (_, _, _, _, _, a) = ch in a end

  fun receiveClientHello chBody =
    case TlsHandshake.decodeClientHello chBody of
        None => raise (Tls "malformed ClientHello")
      | Some ch =>
          let val chMsg = TlsHandshake.encodeMessage (TlsHandshake.ClientHello, chBody) in
            (None, chMsg, "", Some ch, None, None, None, None, None, None, None, False)
          end

  fun serverGroups cfg =
    let val (_, p256, _, _, _, _, _, _, _, _, _) = cfg in
      case p256 of
          Some _ => [TlsHandshake.groupX25519, TlsHandshake.groupSecp256r1]
        | None => [TlsHandshake.groupX25519]
    end

  fun clientKeyShares ch =
    case findExt (chExtensions ch, TlsHandshake.extKeyShare) of
        Some data => (case TlsExtensions.decodeKeyShareCH data of
                          Some xs => xs
                        | None => [])
      | None => []

  fun produceServerHello (st, cfg) =
    let
      val (cipherSuiteOpt, tr, dhe0, clientHelloOpt, cHsS, sHsS, sHsK, sApK,
           cApK, cHsP, errA, conn) = st
      val (cfgX25519, cfgP256, cfgRandom, cfgCS, cfgSessionId, cfgExts,
           cfgChain, cfgRsaDer, cfgSigAlg, cfgNow, cfgSigAlgs) = cfg
      val ch = case clientHelloOpt of None => raise (Tls "no ClientHello") | Some c => c
      val shares = clientKeyShares ch
      val group =
        case TlsExtensions.negotiateGroup (shares, serverGroups cfg) of
            Some g => g
          | None => raise (Tls "no common key_share group")
      val peerPub =
        case List.find (fn e => let val (g, _) = e in g = group end) shares of
            Some e => let val (_, kx) = e in kx end
          | None => raise (Tls "negotiated group has no client share")
      val (serverPub, dhe) =
        if group = TlsHandshake.groupX25519 then
          (X25519.base cfgX25519, X25519.dh cfgX25519 peerPub)
        else raise (Tls "unsupported group (no P-256 in this port)")
      val keyShare = (TlsHandshake.extKeyShare,
                      TlsExtensions.encodeKeyShareSH (group, serverPub))
      val supVer = (TlsHandshake.extSupportedVersions, TlsHandshake.word16ToBytes 0x0304)
      val exts = List.concat [cfgExts, [keyShare, supVer]]
      val sh = (0x0303, cfgRandom, cfgSessionId, cfgCS, 0, exts)
      val shBody = TlsHandshake.encodeServerHello sh
      val shMsg = TlsHandshake.encodeMessage (TlsHandshake.ServerHello, shBody)
      val transcript2 = tr ^ shMsg
      val (es, hs, ms, cHs, sHs, cAp, sAp) =
        TlsKeySchedule.schedule (dhe, transcript2, "")
      val cs = cfgCS
      val (keyLen, ivLen) = suiteKeyIvLen cs
      val sHsKey = TlsKeySchedule.trafficKey (sHs, keyLen)
      val sHsIv = TlsKeySchedule.trafficIv (sHs, ivLen)
      val cHsKey = TlsKeySchedule.trafficKey (cHs, keyLen)
      val cHsIv = TlsKeySchedule.trafficIv (cHs, ivLen)
      val record = TlsRecord.encodePlaintext (TlsRecord.Handshake, shMsg)
      val st2 = (Some cs, transcript2, dhe, clientHelloOpt, Some cHs, Some sHs,
                 Some (sHsKey, sHsIv), None, None, Some (mkProtect (cs, (cHsKey, cHsIv))),
                 None, False)
    in (st2, record) end

  fun produceServerFlight (st, cfg) =
    let
      val (cipherSuiteOpt, tr, dhe, clientHelloOpt, cHsS, sHsSecOpt, sHsKeyOpt,
           sApK, cApK, cHsP, errA, conn) = st
      val (cfgX25519, cfgP256, cfgRandom, cfgCS, cfgSessionId, cfgExts,
           cfgChain, cfgRsaDer, cfgSigAlg, cfgNow, cfgSigAlgs) = cfg
      val cs = optValOf cipherSuiteOpt
      val (keyLen, ivLen) = suiteKeyIvLen cs
      val serverHsSecret = optValOf sHsSecOpt
      val sHsKiv = optValOf sHsKeyOpt
      val eeBody = TlsHandshake.encodeEncryptedExtensions []
      val eeMsg = TlsHandshake.encodeMessage (TlsHandshake.EncryptedExtensions, eeBody)
      val certEntries = List.map (fn der => (der, [])) cfgChain
      val certBody = TlsHandshake.encodeCertificate ("", certEntries)
      val certMsg = TlsHandshake.encodeMessage (TlsHandshake.Certificate, certBody)
      val tBeforeCv = tr ^ eeMsg ^ certMsg
      val cvSigBytes =
        if cfgRsaDer = "" then ""
        else
          let val priv = Rsa.decodePkcs8Der cfgRsaDer in
            TlsKeySchedule.signServerCertVerify (priv, cfgSigAlg, tBeforeCv)
          end
      val cvBody = TlsHandshake.encodeCertificateVerify (cfgSigAlg, cvSigBytes)
      val cvMsg = TlsHandshake.encodeMessage (TlsHandshake.CertificateVerify, cvBody)
      val tBeforeFin = tBeforeCv ^ cvMsg
      val sfKey = TlsKeySchedule.finishedKey serverHsSecret
      val sfVerify = TlsKeySchedule.finishedVerifyData (sfKey, tBeforeFin)
      val sfBody = TlsHandshake.encodeFinished sfVerify
      val sfMsg = TlsHandshake.encodeMessage (TlsHandshake.Finished, sfBody)
      val transcript2 = tBeforeFin ^ sfMsg
      val (es, hs, ms, cHs, sHs, cAp, sAp) =
        TlsKeySchedule.schedule (dhe, tr, transcript2)
      val sApKey = TlsKeySchedule.trafficKey (sAp, keyLen)
      val sApIv = TlsKeySchedule.trafficIv (sAp, ivLen)
      val cApKey = TlsKeySchedule.trafficKey (cAp, keyLen)
      val cApIv = TlsKeySchedule.trafficIv (cAp, ivLen)
      fun emit (prot, msg) =
        let val (body, prot2) =
              TlsRecordProtect.protect (prot, TlsRecord.Handshake, msg, 0)
        in (prot2, TlsRecord.encodeCiphertext (TlsRecord.ApplicationData, body)) end
      val p0 = mkProtect (cs, sHsKiv)
      val (p1, r1) = emit (p0, eeMsg)
      val (p2, r2) = emit (p1, certMsg)
      val (p3, r3) = emit (p2, cvMsg)
      val (p4, r4) = emit (p3, sfMsg)
      val flight = r1 ^ r2 ^ r3 ^ r4
      val st2 = (cipherSuiteOpt, transcript2, dhe, clientHelloOpt, cHsS, sHsSecOpt,
                 sHsKeyOpt, Some (sApKey, sApIv), Some (cApKey, cApIv), cHsP, None, False)
    in (st2, flight) end

  fun setError (st, desc) =
    let val (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, _, a12) = st in
      (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
       Some (TlsAlert.alertDescriptionToByte desc), a12)
    end

  fun markConnected st =
    let val (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, _) = st in
      (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, True)
    end

  fun step (st, input) =
    (let
       val (cipherSuiteOpt, tr, dhe, clientHelloOpt, cHsSecOpt, sHsSecOpt,
            sHsKeyOpt, sApK, cApK, cHsProtOpt, errA, conn) = st
     in
       case errA of
           Some _ => (st, [])
         | None =>
             if input = "" then (st, [])
             else if not conn then
               let
                 fun hsLoop (remaining, prot) =
                   if remaining = "" then (st, [])
                   else
                     case TlsRecord.decodeCiphertext remaining of
                         None => raise (Fatal TlsAlert.DecodeError)
                       | Some (crec, rest) =>
                           let val (ct, enc) = crec in
                             if ct = TlsRecord.ChangeCipherSpec then hsLoop (rest, prot)
                             else if String.size enc > maxCiphertextLen then
                               raise (Fatal TlsAlert.RecordOverflow)
                             else
                               case TlsRecordProtect.unprotect (prot, enc) of
                                   None => raise (Fatal TlsAlert.BadRecordMac)
                                 | Some (innerCt, pt, prot2) =>
                                     (case innerCt of
                                          TlsRecord.Handshake =>
                                            (case TlsHandshake.decodeMessage pt of
                                                 Some (mtb, _) =>
                                                   let val (mt, body) = mtb in
                                                     case mt of
                                                         TlsHandshake.Finished =>
                                                           let
                                                             val cfKey =
                                                               TlsKeySchedule.finishedKey
                                                                 (optValOf cHsSecOpt)
                                                             val expected =
                                                               TlsKeySchedule.finishedVerifyData
                                                                 (cfKey, tr)
                                                           in
                                                             if expected = body
                                                             then (markConnected st, [])
                                                             else raise (Fatal TlsAlert.DecryptError)
                                                           end
                                                       | TlsHandshake.EndOfEarlyData =>
                                                           hsLoop (rest, prot2)
                                                       | _ => raise (Fatal TlsAlert.UnexpectedMessage)
                                                   end
                                               | None => raise (Fatal TlsAlert.UnexpectedMessage))
                                        | _ => raise (Fatal TlsAlert.UnexpectedMessage))
                           end
               in hsLoop (input, optValOf cHsProtOpt) end
             else (st, [])
     end)
    handle Fatal desc => (setError (st, desc), [alertRecord desc])
         | _ => (setError (st, TlsAlert.DecodeError), [alertRecord TlsAlert.DecodeError])

  fun negotiatedCipherSuite st =
    let val (cs, _, _, _, _, _, _, _, _, _, _, _) = st in cs end
  fun transcript st =
    let val (_, t, _, _, _, _, _, _, _, _, _, _) = st in t end
  fun serverAppKey st =
    let val (_, _, _, _, _, _, _, k, _, _, _, _) = st in k end
  fun clientAppKey st =
    let val (_, _, _, _, _, _, _, _, k, _, _, _) = st in k end
  fun error st =
    let val (_, _, _, _, _, _, _, _, _, _, e, _) = st in e end
  fun isConnected st =
    let val (_, _, _, _, _, _, _, _, _, _, _, c) = st in c end
end

(* NOTE: the upstream `Tls` structure is a pure re-export bundle
   (structure TlsRecord = TlsRecord, ...).  CakeML's grammar does not allow
   nested structures / structure abbreviations, so the bundle cannot be
   expressed; the equivalent is that TlsRecord, TlsAlert, TlsHandshake,
   TlsKeySchedule, TlsClient and TlsServer are all top-level structures in
   this compilation unit, directly accessible without the `Tls.` prefix. *)
