(* harden.sml

   J2 robustness / hardening regression tests. Each case captures a
   malformed-input or illegal-field scenario that must produce the CORRECT
   fatal alert and NEVER crash (no exception may escape `step`). These were
   written test-first (red) and then driven green by hardening the pure
   library. They complement the fuzz/OpenSSL-differential harnesses in
   sml-tls-tool, which surface inputs that get distilled into cases here. *)

structure HardenTests =
struct
  open Harness

  fun bytes [] = ""
    | bytes (n :: ns) = String.str (Char.chr n) ^ bytes ns

  val clientRandom = String.implode (List.tabulate (32, fn i => Char.chr ((i + 1) mod 256)))
  val serverRandom = String.implode (List.tabulate (32, fn i => Char.chr ((i * 5 + 9) mod 256)))
  val clientX25519 = String.implode (List.tabulate (32, fn i => Char.chr ((i + 17) mod 256)))

  fun clientCfg () = {
    x25519PrivateKey = clientX25519, p256PrivateKey = NONE,
    clientRandom = clientRandom, legacySessionId = "",
    cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
    extensions = [], serverName = "example.com",
    trustStore = [], now = 0, sigAlgs = [TlsHandshake.sigRsaPssRsaSha256]
  } : TlsClient.clientConfig

  fun alertIs (errOpt, desc) =
    errOpt = SOME (TlsAlert.alertDescriptionToByte desc)

  (* A 32-byte placeholder peer public key. *)
  val peerPub32 = String.implode (List.tabulate (32, fn i => Char.chr ((i * 3) mod 256)))

  (* Build a ServerHello plaintext record from explicit fields. *)
  fun shRecord {legacyVersion, legacyCompression, keyShareKey} =
    let
      val keyShareData = TlsExtensions.encodeKeyShareSH
        {group = TlsHandshake.groupX25519, keyExchange = keyShareKey}
      val exts = [
        {extType = TlsHandshake.extSupportedVersions,
         data = TlsHandshake.word16ToBytes 0wx0304},
        {extType = TlsHandshake.extKeyShare, data = keyShareData}
      ]
      val sh = {
        legacyVersion = legacyVersion, random = serverRandom,
        legacySessionId = "", cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacyCompression = legacyCompression, extensions = exts
      } : TlsHandshake.serverHello
    in
      TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake,
         fragment = TlsHandshake.encodeMessage
           {msgType = TlsHandshake.ServerHello,
            body = TlsHandshake.encodeServerHello sh}}
    end

  (* RFC 8446 §6 alert descriptions and their on-the-wire byte values. *)
  val alertCodes = [
    (TlsAlert.CloseNotify, 0), (TlsAlert.UnexpectedMessage, 10),
    (TlsAlert.BadRecordMac, 20), (TlsAlert.RecordOverflow, 22),
    (TlsAlert.HandshakeFailure, 40), (TlsAlert.BadCertificate, 42),
    (TlsAlert.UnsupportedCertificate, 43), (TlsAlert.CertificateRevoked, 44),
    (TlsAlert.CertificateExpired, 45), (TlsAlert.CertificateUnknown, 46),
    (TlsAlert.IllegalParameter, 47), (TlsAlert.UnknownCa, 48),
    (TlsAlert.AccessDenied, 49), (TlsAlert.DecodeError, 50),
    (TlsAlert.DecryptError, 51), (TlsAlert.ProtocolVersion, 70),
    (TlsAlert.InsufficientSecurity, 71), (TlsAlert.InternalError, 80),
    (TlsAlert.UserCancelled, 90), (TlsAlert.MissingExtension, 109),
    (TlsAlert.UnsupportedExtension, 110), (TlsAlert.UnrecognizedName, 112),
    (TlsAlert.BadCertificateStatus, 113), (TlsAlert.UnknownPskIdentity, 115),
    (TlsAlert.CertificateRequired, 116), (TlsAlert.NoApplicationProtocol, 120)
  ]

  fun run () =
    let
      val () = section "harden: alert wire codes (RFC 8446 sec 6)"
      val () = List.app
        (fn (d, code) =>
           checkBool ("alert byte for code " ^ Int.toString code)
             (true, TlsAlert.alertDescriptionToByte d = Word8.fromInt code))
        alertCodes
      (* Every code must round-trip back to its description (no collisions). *)
      val () = List.app
        (fn (d, code) =>
           checkBool ("alert round-trip for code " ^ Int.toString code)
             (true, TlsAlert.byteToAlertDescription (Word8.fromInt code) = d))
        alertCodes

      val () = section "harden: decoders are total (no escaping exception)"
      (* Regression: fuzzing decodeServerHello / decodeClientHello surfaced an
         uncaught exception. decodeExtensions raised its (generative) local
         `Bad` from a `val` binding -- the length sanity check -- which sits
         OUTSIDE its `handle Bad => NONE`. Because exceptions are generative,
         that escaped the *caller's* own `handle Bad => NONE` too, so any
         message body whose 2-byte extensions-length prefix overstates the
         remaining bytes crashed the decoder instead of returning NONE. *)
      val badExts = bytes [255, 255] (* declares 65535 ext bytes, 0 present *)
      val () = checkBool "harden: decodeExtensions does not raise on short input"
        (true, (ignore (TlsHandshake.decodeExtensions badExts); true)
               handle _ => false)
      val () = checkBool "harden: decodeExtensions returns NONE on length lie"
        (true, TlsHandshake.decodeExtensions badExts = NONE)
      (* A whole ServerHello body whose extensions block lies about its size. *)
      val shBadExtBody =
        TlsHandshake.word16ToBytes 0wx0303          (* legacy_version *)
        ^ serverRandom                              (* 32-byte random   *)
        ^ bytes [0]                                 (* legacy_session_id len = 0 *)
        ^ TlsHandshake.word16ToBytes TlsHandshake.suiteTlsAes128GcmSha256
        ^ bytes [0]                                 (* legacy_compression = 0 *)
        ^ badExts                                   (* lying extensions block  *)
      val () = checkBool "harden: decodeServerHello does not raise on bad exts"
        (true, (ignore (TlsHandshake.decodeServerHello shBadExtBody); true)
               handle _ => false)
      val () = checkBool "harden: decodeServerHello returns NONE on bad exts"
        (true, TlsHandshake.decodeServerHello shBadExtBody = NONE)

      val () = section "harden: Certificate uses 1-byte request_context (RFC 8446 sec 4.4.2)"
      (* certificate_request_context is opaque<0..2^8-1> -- a 1-byte length
         prefix, NOT 3 bytes. A spec-compliant peer (e.g. OpenSSL) sends a
         single 0x00 context byte; our decoder must parse it. Build a
         spec-form Certificate body by hand and require it to decode. *)
      val specCertBody =
        bytes [0]                       (* request_context: 1-byte len = 0 *)
        ^ bytes [0, 0, 9]               (* certificate_list: 3-byte len = 9 *)
        ^ bytes [0, 0, 4] ^ "ABCD"      (* entry: cert_data 3-byte len + data *)
        ^ bytes [0, 0]                  (* entry extensions: 2-byte len = 0   *)
      val () = checkBool "harden: decodeCertificate parses 1-byte context"
        (true, case TlsHandshake.decodeCertificate specCertBody of
                   SOME {certificateRequestContext = "",
                         certificateList = [{certData, extensions = []}]} =>
                     certData = "ABCD"
                 | _ => false)
      (* encodeCertificate must produce that same 1-byte-context wire form. *)
      val () = checkBool "harden: encodeCertificate emits 1-byte context"
        (true, TlsHandshake.encodeCertificate
                 {certificateRequestContext = "",
                  certificateList = [{certData = "ABCD", extensions = []}]}
               = specCertBody)

      val () = section "harden: CertificateVerify signature uses 2-byte length (RFC 8446 sec 4.4.3)"
      (* CertificateVerify.signature is opaque<0..2^16-1> -- a 2-byte length
         prefix, NOT 3 bytes. OpenSSL emits e.g. 08 04 | 01 00 | <256 sig>.
         Our decoder must accept that wire form. *)
      val specCvBody =
        bytes [8, 4]                    (* algorithm = rsa_pss_rsae_sha256 *)
        ^ bytes [0, 4] ^ "SIGN"         (* signature: 2-byte len = 4 + bytes *)
      val () = checkBool "harden: decodeCertificateVerify parses 2-byte length"
        (true, case TlsHandshake.decodeCertificateVerify specCvBody of
                   SOME {sigAlg, sigBytes} =>
                     sigAlg = 0wx0804 andalso sigBytes = "SIGN"
                 | NONE => false)
      val () = checkBool "harden: encodeCertificateVerify emits 2-byte length"
        (true, TlsHandshake.encodeCertificateVerify
                 {sigAlg = 0wx0804, sigBytes = "SIGN"} = specCvBody)

      val () = section "harden: handshake type wire codes (RFC 8446 sec 4)"
      (* Regression: Finished was coded as 0w14 (decimal) instead of its wire
         value 20 (0x14) -- the same decimal/hex literal confusion as the
         alert table. Internal handshakes hid it (both ends agreed on 14);
         the OpenSSL differential exposed it (real peers send 20). Check the
         whole table against the RFC and require a clean round-trip. *)
      val hsTypeCodes = [
        (TlsHandshake.ClientHello, 1), (TlsHandshake.ServerHello, 2),
        (TlsHandshake.NewSessionTicket, 4), (TlsHandshake.EndOfEarlyData, 5),
        (TlsHandshake.EncryptedExtensions, 8), (TlsHandshake.Certificate, 11),
        (TlsHandshake.CertificateRequest, 13), (TlsHandshake.CertificateVerify, 15),
        (TlsHandshake.Finished, 20), (TlsHandshake.KeyUpdate, 24),
        (TlsHandshake.MessageHash, 254)
      ]
      val () = List.app
        (fn (t, code) =>
           checkBool ("hs type wire byte " ^ Int.toString code)
             (true, TlsHandshake.handshakeTypeToByte t = Word8.fromInt code
                    andalso TlsHandshake.byteToHandshakeType (Word8.fromInt code)
                            = SOME t))
        hsTypeCodes

      val () = section "harden: malformed input never crashes step"
      (* Random / truncated bytes fed to a fresh client must not raise. *)
      val (cst0, _) = TlsClient.startHandshake (clientCfg ())
      val garbages = [
        "",                                   (* empty *)
        bytes [0],                            (* 1 byte *)
        bytes [22, 3, 3, 255, 255],           (* header claims 65535-byte frag *)
        bytes [22, 3, 3, 0, 4, 2, 0, 0, 1],   (* Handshake/ServerHello len 1, junk *)
        String.implode (List.tabulate (50, fn i => Char.chr (i * 7 mod 256)))
      ]
      val noCrash =
        List.all
          (fn g => (ignore (TlsClient.step (cst0, g)); true) handle _ => false)
          garbages
      val () = checkBool "harden: garbage records never raise from client.step"
        (true, noCrash)
      (* Every garbage either errors or stays unconnected (never connects). *)
      val () = checkBool "harden: garbage never yields a connected client"
        (true, List.all
                 (fn g => let val (st, _) = TlsClient.step (cst0, g)
                          in not (TlsClient.isConnected st) end
                          handle _ => false)
                 garbages)

      val () = section "harden: ServerHello key_share with wrong-length key"
      (* X25519 shares are always 32 bytes; a 5-byte key must be rejected
         with illegal_parameter, not crash X25519.dh. *)
      val shortKeyRec = shRecord
        {legacyVersion = 0wx0303, legacyCompression = 0w0,
         keyShareKey = bytes [1, 2, 3, 4, 5]}
      val (cstSk, _) = TlsClient.step (cst0, shortKeyRec)
      val () = checkBool "harden: short X25519 key_share -> illegal_parameter"
        (true, alertIs (TlsClient.error cstSk, TlsAlert.IllegalParameter))

      val () = section "harden: illegal legacy fields rejected"
      (* legacy_version other than 0x0303 -> illegal_parameter (§4.1.3). *)
      val verRec = shRecord
        {legacyVersion = 0wx0302, legacyCompression = 0w0, keyShareKey = peerPub32}
      val (cstVer, _) = TlsClient.step (cst0, verRec)
      val () = checkBool "harden: SH legacy_version != 0x0303 -> illegal_parameter"
        (true, alertIs (TlsClient.error cstVer, TlsAlert.IllegalParameter))
      (* legacy_compression_method other than 0 -> illegal_parameter. *)
      val compRec = shRecord
        {legacyVersion = 0wx0303, legacyCompression = 0w1, keyShareKey = peerPub32}
      val (cstComp, _) = TlsClient.step (cst0, compRec)
      val () = checkBool "harden: SH legacy_compression != 0 -> illegal_parameter"
        (true, alertIs (TlsClient.error cstComp, TlsAlert.IllegalParameter))

      val () = section "harden: oversized record -> record_overflow"
      (* A TLSCiphertext whose length exceeds 2^14 + 256 must be rejected
         with record_overflow before any AEAD work. *)
      val (sst0, _) =
        let
          val (c0, ch) = TlsClient.startHandshake (clientCfg ())
          val chBody =
            case TlsRecord.decodePlaintext ch of
                SOME (r, _) =>
                  (case TlsHandshake.decodeMessage (#fragment r) of
                       SOME ({body, ...}, _) => body | _ => "")
              | _ => ""
          val s0 = TlsServer.receiveClientHello chBody
          val scfg = {
            x25519PrivateKey = clientX25519, p256PrivateKey = NONE,
            serverRandom = serverRandom,
            cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
            legacySessionId = "", extensions = [], certChain = [],
            rsaPrivateKeyDer = "", sigAlg = TlsHandshake.sigRsaPssRsaSha256,
            now = 0, sigAlgs = []
          } : TlsServer.serverConfig
        in TlsServer.produceServerHello (s0, scfg) end
      val bigRecord = TlsRecord.encodeCiphertext
        {contentType = TlsRecord.ApplicationData,
         encryptedRecord = String.implode
           (List.tabulate (16384 + 257, fn _ => Char.chr 0))}
      val (sstBig, _) = TlsServer.step (sst0, bigRecord)
      val () = checkBool "harden: oversized ciphertext -> record_overflow"
        (true, alertIs (TlsServer.error sstBig, TlsAlert.RecordOverflow))
    in
      ()
    end
end
