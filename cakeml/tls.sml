(* tls.sml -- CakeML port of the sml-tls core protocol structures.

   Ports TlsRecord, TlsAlert, TlsHandshake, TlsKeySchedule (from the
   upstream tls.sml) and TlsRecordProtect (from recordprotect.sml) onto
   the already-ported CakeML crypto tower.

   Depends, earlier in the SAME compilation unit, on the ported tower
   structures: Sha256, Hmac, Kdf (cakeml/kdf.sml), Rsa (cakeml/rsa.sml)
   and Aead (cakeml/aead.sml).  See tls_PORT_NOTES.md for the full
   dialect-gap list and concatenation order.

   Dialect choices (vs the upstream SML):
     - CakeML has no Word16/Word32 -> all 16/32-bit wire values are
       native `int`; serialization is by div/mod, parsing by *256+.
     - CakeML has no records -> every record type is a tuple, every
       record-argument function takes a tuple, and every #field selector
       becomes a tuple destructure.
     - CakeML has no `Byte` structure -> `Char.chr`/`Char.ord` over int
       bytes (0..255); the few byte XORs use Word8.
     - Some/None/True/False; curried basis calls (String.sub s i,
       String.substring s a b, String.extract s a None, List.tabulate n f);
       single multi-clause functions rewritten with case/if. *)

structure TlsRecord = struct
  datatype contentType =
      Invalid
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData

  fun contentTypeToByte ct =
    case ct of
        Invalid => 0
      | ChangeCipherSpec => 20
      | Alert => 21
      | Handshake => 22
      | ApplicationData => 23

  fun byteToContentType b =
    if b = 0 then Some Invalid
    else if b = 20 then Some ChangeCipherSpec
    else if b = 21 then Some Alert
    else if b = 22 then Some Handshake
    else if b = 23 then Some ApplicationData
    else None

  (* 0x0303 -- TLS 1.2 legacy record version, used on the wire even for 1.3 *)
  val legacyVersion = 0x0303

  (* tlsPlaintext  = (contentType, fragment)
     tlsCiphertext = (contentType, encryptedRecord) *)

  (* 5-byte header: [type:1][version:2][length:2] then fragment. *)
  fun encodePlaintext (ct, fragment) =
    let
      val n = String.size fragment
      val hdr = String.implode
        [ Char.chr (contentTypeToByte ct)
        , Char.chr (legacyVersion div 256)
        , Char.chr (legacyVersion mod 256)
        , Char.chr (n div 256)
        , Char.chr (n mod 256) ]
    in hdr ^ fragment end

  fun decodePlaintext s =
    if String.size s < 5 then None
    else
      let
        val b0 = Char.ord (String.sub s 0)
        val hi = Char.ord (String.sub s 3)
        val lo = Char.ord (String.sub s 4)
        val n = hi * 256 + lo
      in
        case byteToContentType b0 of
            None => None
          | Some ct =>
              if String.size s < 5 + n then None
              else
                let
                  val frag = String.substring s 5 n
                  val rest = String.extract s (5 + n) None
                in Some ((ct, frag), rest) end
      end

  fun encodeCiphertext (ct, encryptedRecord) =
    encodePlaintext (ct, encryptedRecord)

  fun decodeCiphertext s = decodePlaintext s
end

structure TlsAlert = struct
  datatype alertLevel = Warning | Fatal

  fun alertLevelToByte l = case l of Warning => 1 | Fatal => 2

  fun byteToAlertLevel b =
    if b = 1 then Some Warning
    else if b = 2 then Some Fatal
    else None

  datatype alertDescription =
      CloseNotify
    | UnexpectedMessage
    | BadRecordMac
    | RecordOverflow
    | HandshakeFailure
    | BadCertificate
    | UnsupportedCertificate
    | CertificateRevoked
    | CertificateExpired
    | CertificateUnknown
    | IllegalParameter
    | UnknownCa
    | AccessDenied
    | DecodeError
    | DecryptError
    | ProtocolVersion
    | InsufficientSecurity
    | InternalError
    | UserCancelled
    | MissingExtension
    | UnsupportedExtension
    | UnrecognizedName
    | BadCertificateStatus
    | UnknownPskIdentity
    | CertificateRequired
    | NoApplicationProtocol
    | Other int

  (* RFC 8446 6.2 alert codes (decimal). *)
  fun alertDescriptionToByte d =
    case d of
        CloseNotify => 0
      | UnexpectedMessage => 10
      | BadRecordMac => 20
      | RecordOverflow => 22
      | HandshakeFailure => 40
      | BadCertificate => 42
      | UnsupportedCertificate => 43
      | CertificateRevoked => 44
      | CertificateExpired => 45
      | CertificateUnknown => 46
      | IllegalParameter => 47
      | UnknownCa => 48
      | AccessDenied => 49
      | DecodeError => 50
      | DecryptError => 51
      | ProtocolVersion => 70
      | InsufficientSecurity => 71
      | InternalError => 80
      | UserCancelled => 90
      | MissingExtension => 109
      | UnsupportedExtension => 110
      | UnrecognizedName => 112
      | BadCertificateStatus => 113
      | UnknownPskIdentity => 115
      | CertificateRequired => 116
      | NoApplicationProtocol => 120
      | Other w => w

  fun byteToAlertDescription b =
    if b = 0 then CloseNotify
    else if b = 10 then UnexpectedMessage
    else if b = 20 then BadRecordMac
    else if b = 22 then RecordOverflow
    else if b = 40 then HandshakeFailure
    else if b = 42 then BadCertificate
    else if b = 43 then UnsupportedCertificate
    else if b = 44 then CertificateRevoked
    else if b = 45 then CertificateExpired
    else if b = 46 then CertificateUnknown
    else if b = 47 then IllegalParameter
    else if b = 48 then UnknownCa
    else if b = 49 then AccessDenied
    else if b = 50 then DecodeError
    else if b = 51 then DecryptError
    else if b = 70 then ProtocolVersion
    else if b = 71 then InsufficientSecurity
    else if b = 80 then InternalError
    else if b = 90 then UserCancelled
    else if b = 109 then MissingExtension
    else if b = 110 then UnsupportedExtension
    else if b = 112 then UnrecognizedName
    else if b = 113 then BadCertificateStatus
    else if b = 115 then UnknownPskIdentity
    else if b = 116 then CertificateRequired
    else if b = 120 then NoApplicationProtocol
    else Other b

  (* alert = (alertLevel, alertDescription) *)
  fun encode (level, description) =
    String.implode
      [ Char.chr (alertLevelToByte level)
      , Char.chr (alertDescriptionToByte description) ]

  fun decode s =
    if String.size s <> 2 then None
    else
      let
        val l = Char.ord (String.sub s 0)
        val d = Char.ord (String.sub s 1)
      in
        case byteToAlertLevel l of
            None => None
          | Some lvl => Some (lvl, byteToAlertDescription d)
      end
end

structure TlsHandshake = struct
  exception Bad

  datatype handshakeType =
      ClientHello
    | ServerHello
    | NewSessionTicket
    | EndOfEarlyData
    | EncryptedExtensions
    | Certificate
    | CertificateRequest
    | CertificateVerify
    | Finished
    | KeyUpdate
    | MessageHash

  fun handshakeTypeToByte t =
    case t of
        ClientHello => 1
      | ServerHello => 2
      | NewSessionTicket => 4
      | EndOfEarlyData => 5
      | EncryptedExtensions => 8
      | Certificate => 11
      | CertificateRequest => 13
      | CertificateVerify => 15
      | Finished => 20
      | KeyUpdate => 24
      | MessageHash => 254

  fun byteToHandshakeType b =
    if b = 1 then Some ClientHello
    else if b = 2 then Some ServerHello
    else if b = 4 then Some NewSessionTicket
    else if b = 5 then Some EndOfEarlyData
    else if b = 8 then Some EncryptedExtensions
    else if b = 11 then Some Certificate
    else if b = 13 then Some CertificateRequest
    else if b = 15 then Some CertificateVerify
    else if b = 20 then Some Finished
    else if b = 24 then Some KeyUpdate
    else if b = 254 then Some MessageHash
    else None

  (* handshakeMessage = (msgType, body) *)
  fun encodeMessage (msgType, body) =
    let
      val n = String.size body
      val hdr = String.implode
        [ Char.chr (handshakeTypeToByte msgType)
        , Char.chr ((n div 65536) mod 256)
        , Char.chr ((n div 256) mod 256)
        , Char.chr (n mod 256) ]
    in hdr ^ body end

  fun decodeMessage s =
    if String.size s < 4 then None
    else
      let
        val t = Char.ord (String.sub s 0)
        val b1 = Char.ord (String.sub s 1)
        val b2 = Char.ord (String.sub s 2)
        val b3 = Char.ord (String.sub s 3)
        val n = b1 * 65536 + b2 * 256 + b3
      in
        case byteToHandshakeType t of
            None => None
          | Some ht =>
              if String.size s < 4 + n then None
              else
                let
                  val body = String.substring s 4 n
                  val rest = String.extract s (4 + n) None
                in Some ((ht, body), rest) end
      end

  (* extension = (extType:int, data:string) *)
  fun word16ToBytes w =
    String.implode [ Char.chr ((w div 256) mod 256), Char.chr (w mod 256) ]

  fun bytesToWord16 (hi, lo) = hi * 256 + lo

  fun encodeExtensions exts =
    let
      val total = List.foldl (fn (et, d) => fn n => n + 4 + String.size d) 0 exts
      val header = word16ToBytes total
      fun one (et, d) =
        word16ToBytes et ^ word16ToBytes (String.size d) ^ d
    in header ^ String.concat (List.map one exts) end

  fun decodeExtensions s =
    if String.size s < 2 then None
    else
      let
        val sz = String.size s
        val total = bytesToWord16 (Char.ord (String.sub s 0), Char.ord (String.sub s 1))
        fun loop i acc =
          if i >= 2 + total then Some (List.rev acc)
          else if i + 4 > sz then None
          else
            let
              val et = bytesToWord16 (Char.ord (String.sub s i),
                                      Char.ord (String.sub s (i + 1)))
              val dl = bytesToWord16 (Char.ord (String.sub s (i + 2)),
                                      Char.ord (String.sub s (i + 3)))
            in
              if i + 4 + dl > sz then None
              else loop (i + 4 + dl) ((et, String.substring s (i + 4) dl) :: acc)
            end
      in
        if sz < 2 + total then None else loop 2 []
      end

  val extServerName = 0x0000
  val extSupportedGroups = 0x000A
  val extSignatureAlgorithms = 0x000D
  val extSupportedVersions = 0x002B
  val extKeyShare = 0x0033
  val extPreSharedKey = 0x0029
  val extEarlyData = 0x002A
  val extCookie = 0x002C
  val extPskKeyExchangeModes = 0x002D

  val helloRetryRequestRandom =
    String.implode (List.map Char.chr
      [ 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11
      , 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
      , 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E
      , 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C ])

  (* clientHello = (legacyVersion, random, legacySessionId,
                    cipherSuites:int list, legacyCompression:int list,
                    extensions:(int*string) list) *)
  fun encodeWord16List ws =
    let
      val total = List.length ws * 2
      val body = String.concat (List.map word16ToBytes ws)
    in word16ToBytes total ^ body end

  fun encodeWord8List ws =
    let
      val total = List.length ws
      val body = String.implode (List.map Char.chr ws)
    in String.str (Char.chr total) ^ body end

  fun encodeClientHello (legacyVersion, random, legacySessionId,
                         cipherSuites, legacyCompression, extensions) =
    let
      val sessionIdLen = String.size legacySessionId
      val sessionIdBytes = String.str (Char.chr sessionIdLen) ^ legacySessionId
      val extBlock = encodeExtensions extensions
    in
      word16ToBytes legacyVersion
      ^ random
      ^ sessionIdBytes
      ^ encodeWord16List cipherSuites
      ^ encodeWord8List legacyCompression
      ^ extBlock
    end

  fun decodeClientHello s =
    let
      val len = String.size s
      fun at i = if i < len then Char.ord (String.sub s i) else raise Bad
      fun w16 i =
        if i + 1 < len then
          bytesToWord16 (Char.ord (String.sub s i), Char.ord (String.sub s (i + 1)))
        else raise Bad
      fun sub i n = if i + n <= len then String.substring s i n else raise Bad
    in
      (Some (let
        val legacyVersion = w16 0
        val random = sub 2 32
        val sidLen = at 34
        val sidStart = 35
        val legacySessionId = sub sidStart sidLen
        val csStart = sidStart + sidLen
        val csTotal = w16 csStart
        val csCount = csTotal div 2
        val csBodyStart = csStart + 2
        fun readCS i k acc =
          if k = 0 then (List.rev acc, i)
          else readCS (i + 2) (k - 1) (w16 i :: acc)
        val (cipherSuites, compStart) = readCS csBodyStart csCount []
        val compLen = at compStart
        val compBodyStart = compStart + 1
        fun readComp i k acc =
          if k = 0 then (List.rev acc, i)
          else readComp (i + 1) (k - 1) (at i :: acc)
        val (legacyCompression, extStart) = readComp compBodyStart compLen []
        val extensions =
          if extStart >= len then []
          else
            case decodeExtensions (String.extract s extStart None) of
                None => raise Bad
              | Some es => es
      in
        (legacyVersion, random, legacySessionId, cipherSuites,
         legacyCompression, extensions)
      end)) handle Bad => None
    end

  (* serverHello = (legacyVersion, random, legacySessionId,
                    cipherSuite:int, legacyCompression:int, extensions) *)
  fun encodeServerHello (legacyVersion, random, legacySessionId,
                         cipherSuite, legacyCompression, extensions) =
    let
      val sessionIdLen = String.size legacySessionId
      val extBlock = encodeExtensions extensions
    in
      word16ToBytes legacyVersion
      ^ random
      ^ String.str (Char.chr sessionIdLen) ^ legacySessionId
      ^ word16ToBytes cipherSuite
      ^ String.str (Char.chr legacyCompression)
      ^ extBlock
    end

  fun decodeServerHello s =
    let
      val len = String.size s
      fun at i = if i < len then Char.ord (String.sub s i) else raise Bad
      fun w16 i =
        if i + 1 < len then
          bytesToWord16 (Char.ord (String.sub s i), Char.ord (String.sub s (i + 1)))
        else raise Bad
      fun sub i n = if i + n <= len then String.substring s i n else raise Bad
    in
      (Some (let
        val legacyVersion = w16 0
        val random = sub 2 32
        val sidLen = at 34
        val sidStart = 35
        val legacySessionId = sub sidStart sidLen
        val csStart = sidStart + sidLen
        val cipherSuite = w16 csStart
        val compStart = csStart + 2
        val legacyCompression = at compStart
        val extStart = compStart + 1
        val extensions =
          if extStart >= len then []
          else
            case decodeExtensions (String.extract s extStart None) of
                None => raise Bad
              | Some es => es
      in
        (legacyVersion, random, legacySessionId, cipherSuite,
         legacyCompression, extensions)
      end)) handle Bad => None
    end

  (* encryptedExtensions = extension list *)
  fun encodeEncryptedExtensions exts = encodeExtensions exts
  fun decodeEncryptedExtensions s = decodeExtensions s

  (* certificateEntry = (certData, extensions)
     certificate     = (certificateRequestContext, certificateList) *)
  fun len3 n =
    String.implode
      [ Char.chr ((n div 65536) mod 256)
      , Char.chr ((n div 256) mod 256)
      , Char.chr (n mod 256) ]

  fun readLen3 s i =
    if i + 3 > String.size s then None
    else
      let
        val b1 = Char.ord (String.sub s i)
        val b2 = Char.ord (String.sub s (i + 1))
        val b3 = Char.ord (String.sub s (i + 2))
      in Some (b1 * 65536 + b2 * 256 + b3, i + 3) end

  fun encodeCertificate (certificateRequestContext, certificateList) =
    let
      val ctxLen = String.size certificateRequestContext
      val ctx = String.str (Char.chr (ctxLen mod 256)) ^ certificateRequestContext
      fun oneEntry (certData, extensions) =
        len3 (String.size certData) ^ certData ^ encodeExtensions extensions
      val entries = String.concat (List.map oneEntry certificateList)
      val entriesLen = String.size entries
    in ctx ^ len3 entriesLen ^ entries end

  fun decodeCertificate s =
    let
      val len = String.size s
    in
      if len < 1 then None
      else
        let
          val ctxLen = Char.ord (String.sub s 0)
          val i = 1
        in
          if i + ctxLen > len then None
          else
            let
              val ctx = String.substring s i ctxLen
              val listStart = i + ctxLen
            in
              case readLen3 s listStart of
                  None => None
                | Some (total, ip) =>
                    if ip + total > len then None
                    else
                      let
                        val block = String.substring s ip total
                        val blen = String.size block
                        fun loop k acc =
                          if k >= blen then Some (List.rev acc)
                          else
                            (case readLen3 block k of
                                 None => None
                               | Some (cl, certDataStart) =>
                                   if certDataStart + cl > blen then None
                                   else
                                     let
                                       val certData = String.substring block certDataStart cl
                                       val extStart = certDataStart + cl
                                     in
                                       if extStart >= blen then
                                         loop blen ((certData, []) :: acc)
                                       else
                                         case decodeExtensions
                                                (String.extract block extStart None) of
                                             None => None
                                           | Some es =>
                                               let
                                                 val entryEnd =
                                                   extStart + String.size (encodeExtensions es)
                                               in
                                                 loop entryEnd ((certData, es) :: acc)
                                               end
                                     end)
                      in
                        case loop 0 [] of
                            None => None
                          | Some entries => Some (ctx, entries)
                      end
            end
        end
    end

  (* certificateVerify = (sigAlg:int, sigBytes:string) *)
  fun encodeCertificateVerify (sigAlg, sigBytes) =
    word16ToBytes sigAlg
    ^ word16ToBytes (String.size sigBytes) ^ sigBytes

  fun decodeCertificateVerify s =
    if String.size s < 4 then None
    else
      let
        val sigAlg = bytesToWord16 (Char.ord (String.sub s 0), Char.ord (String.sub s 1))
        val n = bytesToWord16 (Char.ord (String.sub s 2), Char.ord (String.sub s 3))
        val i = 4
      in
        if i + n > String.size s then None
        else Some (sigAlg, String.substring s i n)
      end

  (* finished = verifyData (string) *)
  fun encodeFinished verifyData = verifyData
  fun decodeFinished s = if String.size s = 0 then None else Some s

  (* newSessionTicket = (ticketLifetime:int, ticketAgeAdd:int,
                         ticketNonce, ticket, extensions) *)
  fun word32ToBytes w =
    String.implode
      [ Char.chr ((w div 16777216) mod 256)
      , Char.chr ((w div 65536) mod 256)
      , Char.chr ((w div 256) mod 256)
      , Char.chr (w mod 256) ]

  fun bytesToWord32 (a, b, c, d) =
    a * 16777216 + b * 65536 + c * 256 + d

  fun encodeNewSessionTicket (ticketLifetime, ticketAgeAdd, ticketNonce,
                              ticket, extensions) =
    word32ToBytes ticketLifetime
    ^ word32ToBytes ticketAgeAdd
    ^ String.str (Char.chr (String.size ticketNonce)) ^ ticketNonce
    ^ len3 (String.size ticket) ^ ticket
    ^ encodeExtensions extensions

  fun decodeNewSessionTicket s =
    if String.size s < 8 then None
    else
      let
        val ticketLifetime = bytesToWord32
          (Char.ord (String.sub s 0), Char.ord (String.sub s 1),
           Char.ord (String.sub s 2), Char.ord (String.sub s 3))
        val ticketAgeAdd = bytesToWord32
          (Char.ord (String.sub s 4), Char.ord (String.sub s 5),
           Char.ord (String.sub s 6), Char.ord (String.sub s 7))
      in
        if String.size s < 9 then None
        else
          let val nonceLen = Char.ord (String.sub s 8) in
            if 9 + nonceLen > String.size s then None
            else
              let
                val ticketNonce = String.substring s 9 nonceLen
                val ticketStart = 9 + nonceLen
              in
                case readLen3 s ticketStart of
                    None => None
                  | Some (tl, i) =>
                      if i + tl > String.size s then None
                      else
                        let
                          val ticket = String.substring s i tl
                          val extStart = i + tl
                        in
                          if extStart >= String.size s then
                            Some (ticketLifetime, ticketAgeAdd, ticketNonce, ticket, [])
                          else
                            case decodeExtensions (String.extract s extStart None) of
                                None => None
                              | Some exts =>
                                  Some (ticketLifetime, ticketAgeAdd, ticketNonce,
                                        ticket, exts)
                        end
              end
          end
      end

  (* cipher suites (B.4) *)
  val suiteTlsAes128GcmSha256 = 0x1301
  val suiteTlsAes256GcmSha384 = 0x1302
  val suiteTlsChaCha20Poly1305 = 0x1303

  (* signature schemes (4.2.3 / RFC 8017) *)
  val sigRsaPssRsaSha256 = 0x0804
  val sigRsaPssRsaSha384 = 0x0805
  val sigRsaPssRsaSha512 = 0x0806
  val sigEcdsaSecp256r1Sha256 = 0x0403

  (* named groups (4.2.7) *)
  val groupX25519 = 0x001D
  val groupSecp256r1 = 0x0017
end

structure TlsKeySchedule = struct
  exception KsErr string

  val hashLen = 32

  val zeros = String.implode (List.tabulate hashLen (fn _ => Char.chr 0))

  val tls13Prefix = "tls13 "

  (* HKDF-Expand-Label.  Args: (secret, label, context, length). *)
  fun hkdfExpandLabel (secret, label, context, length) =
    let
      val fullLabel = tls13Prefix ^ label
      val labelLen = String.size fullLabel
      val ctxLen = String.size context
      val info =
        String.implode
          [ Char.chr ((length div 256) mod 256)
          , Char.chr (length mod 256)
          , Char.chr labelLen ]
        ^ fullLabel
        ^ String.str (Char.chr ctxLen)
        ^ context
    in
      Kdf.hkdfExpand (secret, info, length)
    end

  fun transcriptHash transcript = Sha256.digest transcript

  (* Args: (secret, label, transcript). *)
  fun deriveSecret (secret, label, transcript) =
    hkdfExpandLabel (secret, label, transcriptHash transcript, hashLen)

  (* HKDF-Extract.  Args: (salt, ikm). *)
  fun extract (salt, ikm) = Kdf.hkdfExtract (salt, ikm)

  val deriveLabel = "derived"

  fun earlySecret psk = extract (zeros, psk)

  val emptyHash = Sha256.digest ""

  fun handshakeSecret (earlySecretV, dhe) =
    let
      val derived = hkdfExpandLabel (earlySecretV, deriveLabel, emptyHash, hashLen)
    in extract (derived, dhe) end

  fun masterSecret handshakeSecretV =
    let
      val derived = hkdfExpandLabel (handshakeSecretV, deriveLabel, emptyHash, hashLen)
    in extract (derived, zeros) end

  fun trafficKey (secret, keyLength) =
    hkdfExpandLabel (secret, "key", "", keyLength)

  fun trafficIv (secret, ivLength) =
    hkdfExpandLabel (secret, "iv", "", ivLength)

  fun finishedKey secret =
    hkdfExpandLabel (secret, "finished", "", hashLen)

  val certificateVerifyPrefix =
    String.implode (List.tabulate 64 (fn _ => Char.chr 32))

  val clientCertVerifyContext = "TLS 1.3, client CertificateVerify"
  val serverCertVerifyContext = "TLS 1.3, server CertificateVerify"

  (* Args: (contextString, transcriptHash). *)
  fun certificateVerifyInput (contextString, transcriptHashV) =
    certificateVerifyPrefix ^ contextString ^ String.str (Char.chr 0) ^ transcriptHashV

  val sigRsaPssRsaeSha256 = 0x0804
  val cvFixedSalt = String.implode (List.tabulate 32 (fn _ => Char.chr 0))

  (* Args: (priv, sigAlg, transcript). *)
  fun signServerCertVerify (priv, sigAlg, transcript) =
    if sigAlg = sigRsaPssRsaeSha256 then
      let
        val input = certificateVerifyInput
          (serverCertVerifyContext, transcriptHash transcript)
      in
        Rsa.signPss (priv, Rsa.SHA256, cvFixedSalt, input)
      end
    else raise KsErr "signServerCertVerify: unsupported signature scheme"

  (* Args: (pub, sigAlg, transcript, sgn). *)
  fun verifyServerCertVerify (pub, sigAlg, transcript, sgn) =
    if sigAlg = sigRsaPssRsaeSha256 then
      let
        val input = certificateVerifyInput
          (serverCertVerifyContext, transcriptHash transcript)
      in
        Rsa.verifyPss (pub, Rsa.SHA256, 32, input, sgn)
      end
    else False

  (* Args: (finishedKey, transcript). *)
  fun finishedVerifyData (finishedKeyV, transcript) =
    Hmac.hmacSha256 finishedKeyV (transcriptHash transcript)

  (* ---- PSK resumption ---- *)
  fun resumptionMasterSecret (masterSecretV, transcript) =
    deriveSecret (masterSecretV, "res master", transcript)

  fun resumptionPsk (resumptionMasterSecretV, ticketNonce) =
    hkdfExpandLabel (resumptionMasterSecretV, "resumption", ticketNonce, hashLen)

  fun binderKey psk =
    let val es = extract (zeros, psk)
    in deriveSecret (es, "res binder", "") end

  fun binderFinishedKey psk =
    hkdfExpandLabel (binderKey psk, "finished", "", hashLen)

  fun pskBinder (psk, transcript) =
    Hmac.hmacSha256 (binderFinishedKey psk) (transcriptHash transcript)

  (* keySchedule = (earlySecret, handshakeSecret, masterSecret,
                    clientHandshakeSecret, serverHandshakeSecret,
                    clientAppSecret, serverAppSecret) *)
  fun schedule (dhe, handshakeTranscript, applicationTranscript) =
    let
      val es = earlySecret zeros
      val hs = handshakeSecret (es, dhe)
      val ms = masterSecret hs
      val cHs = deriveSecret (hs, "c hs traffic", handshakeTranscript)
      val sHs = deriveSecret (hs, "s hs traffic", handshakeTranscript)
      val cAp = deriveSecret (ms, "c ap traffic", applicationTranscript)
      val sAp = deriveSecret (ms, "s ap traffic", applicationTranscript)
    in
      (es, hs, ms, cHs, sHs, cAp, sAp)
    end
end

(* ================================================================== *)
(* TlsRecordProtect (recordprotect.sml) -- AEAD record protection.     *)
(* Depends on Aead (earlier) and TlsRecord (above).                    *)
(* ================================================================== *)

structure TlsRecordProtect = struct
  (* state = (key, iv, alg, seq) *)
  fun algForKey k =
    if String.size k = 16 then Aead.AAesGcm128
    else if String.size k = 32 then Aead.AAesGcm256
    else raise Aead.Aead ("TlsRecordProtect: unsupported key length "
                          ^ Int.toString (String.size k))

  fun init (key, iv) = (key, iv, algForKey key, 0)
  fun initWithAlg (key, iv, alg) = (key, iv, alg, 0)

  fun seqBytes seq =
    let
      val w = Word64.fromInt seq
      fun byte i = Char.chr (Word64.toInt (Word64.andb (Word64.>> w i) 0wxFF))
      val be8 = String.implode
        [ byte 56, byte 48, byte 40, byte 32, byte 24, byte 16, byte 8, byte 0 ]
      val pad = String.implode (List.tabulate 4 (fn _ => Char.chr 0))
    in pad ^ be8 end

  fun nonce (iv, seq) =
    let
      val nl = 12
      val pad = seqBytes seq
      fun xb a b =
        Char.chr (Word8.toInt
          (Word8.xorb (Word8.fromInt (Char.ord a)) (Word8.fromInt (Char.ord b))))
      fun loop i acc =
        if i >= nl then String.implode (List.rev acc)
        else loop (i + 1) (xb (String.sub iv i) (String.sub pad i) :: acc)
    in
      if String.size iv <> nl then
        raise Aead.Aead "TlsRecordProtect: bad IV length"
      else loop 0 []
    end

  val maxPlaintext = 16384

  fun contentTypeToByte ct =
    case ct of
        TlsRecord.Invalid => 0
      | TlsRecord.ChangeCipherSpec => 20
      | TlsRecord.Alert => 21
      | TlsRecord.Handshake => 22
      | TlsRecord.ApplicationData => 23

  fun byteToContentType b =
    if b = 0 then Some TlsRecord.Invalid
    else if b = 20 then Some TlsRecord.ChangeCipherSpec
    else if b = 21 then Some TlsRecord.Alert
    else if b = 22 then Some TlsRecord.Handshake
    else if b = 23 then Some TlsRecord.ApplicationData
    else None

  fun aadHeader n =
    String.implode
      [ Char.chr 23, Char.chr 3, Char.chr 3
      , Char.chr (n div 256), Char.chr (n mod 256) ]

  (* Args: (state, innerType, plaintext, pad) -> (sealed, state'). *)
  fun protect (state, innerType, plaintext, pad) =
    let
      val (key, iv, alg, seq) = state
      val ptLen = String.size plaintext
      val _ = if ptLen > maxPlaintext then
                raise Aead.Aead "TlsRecordProtect.protect: record_overflow"
              else if pad < 0 then
                raise Aead.Aead "TlsRecordProtect.protect: negative pad"
              else ()
      val inner = plaintext
        ^ String.str (Char.chr (contentTypeToByte innerType))
        ^ String.implode (List.tabulate pad (fn _ => Char.chr 0))
      val n = nonce (iv, seq)
      val aad = aadHeader (String.size inner + Aead.tagLen)
      val sealed = Aead.seal alg (key, n, aad, inner)
      val st2 = (key, iv, alg, seq + 1)
    in (sealed, st2) end

  (* Args: (state, record) -> (contentType, plaintext, state') option. *)
  fun unprotect (state, record) =
    let
      val (key, iv, alg, seq) = state
      val n = nonce (iv, seq)
      val aad = aadHeader (String.size record)
    in
      case Aead.open' alg (key, n, aad, record) of
          None => None
        | Some inner =>
            let
              val len = String.size inner
              fun findType i =
                if i < 0 then None
                else
                  let val b = Char.ord (String.sub inner i) in
                    if b = 0 then findType (i - 1)
                    else if i = 0 then None
                    else
                      case byteToContentType b of
                          None => None
                        | Some ct => Some (ct, String.substring inner 0 i)
                  end
            in
              case findType (len - 1) of
                  None => None
                | Some (ct, pt) =>
                    if String.size pt > maxPlaintext then None
                    else Some (ct, pt, (key, iv, alg, seq + 1))
            end
    end
end
