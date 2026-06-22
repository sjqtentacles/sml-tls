(* hs2.sml

   Tests for the remaining TLS 1.3 handshake features wired in after J1:
   HelloRetryRequest + cookie (with the §4.4.1 synthetic-message transcript
   substitution), 0-RTT / early_data reject, and PSK resumption pieces
   (binder MAC per §4.2.11). These exercise the TlsClient / TlsServer state
   machine end-to-end, alongside the codec-level unit tests in test.sml. *)

structure Hs2Tests =
struct
  open Harness

  (* ---- byte helpers (mirrors test.sml) ---- *)
  fun bytes [] = ""
    | bytes (n :: ns) = String.str (Char.chr n) ^ bytes ns

  fun bytesEq (a, b) = String.size a = String.size b andalso a = b

  fun toHex s =
    let
      fun one c =
        let val v = Char.ord c
            val h = v div 16 and l = v mod 16
            fun d n = if n < 10 then Char.chr (Char.ord #"0" + n)
                      else Char.chr (Char.ord #"a" + n - 10)
        in String.implode [d h, d l] end
    in String.concat (List.map one (String.explode s)) end

  fun checkBytes (name, expected, actual) =
    if bytesEq (expected, actual) then check name true
    else (print ("  FAIL - " ^ name ^ ": " ^ toHex expected ^ " <> "
                 ^ toHex actual ^ "\n"); check name false)

  (* 32-byte test material. *)
  fun pat f = String.implode (List.tabulate (32, fn i => Char.chr (f i mod 256)))
  val clientRandom = pat (fn i => i + 1)
  val serverRandom = pat (fn i => i * 5 + 9)
  val clientX25519 = pat (fn i => i + 17)
  val serverX25519 = pat (fn i => i * 7 + 3)
  val clientP256   = pat (fn i => i + 1)
  val serverP256   = pat (fn i => i * 3 + 7)

  (* Pull a handshake-message body out of a plaintext record. *)
  fun hsBody record =
    case TlsRecord.decodePlaintext record of
        SOME (r, _) =>
          (case TlsHandshake.decodeMessage (#fragment r) of
               SOME ({body, ...}, _) => body
             | _ => raise Fail "hsBody: no handshake message")
      | _ => raise Fail "hsBody: not a plaintext record"

  fun alertIs (errOpt, desc) =
    errOpt = SOME (TlsAlert.alertDescriptionToByte desc)

  (* A client config offering X25519 up front but advertising secp256r1 too
     (P-256 key configured), so a server can force a P-256 retry via HRR. *)
  fun clientCfg () = {
    x25519PrivateKey = clientX25519,
    p256PrivateKey = SOME clientP256,
    clientRandom = clientRandom,
    legacySessionId = bytes (List.tabulate (32, fn i => i)),
    cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
    extensions = [],
    serverName = "example.com",
    trustStore = [],
    now = 0,
    sigAlgs = [TlsHandshake.sigRsaPssRsaSha256]
  } : TlsClient.clientConfig

  fun serverCfg () = {
    x25519PrivateKey = serverX25519,
    p256PrivateKey = SOME serverP256,
    serverRandom = serverRandom,
    cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
    legacySessionId = bytes (List.tabulate (32, fn i => i)),
    extensions = [],
    certChain = [],
    rsaPrivateKeyDer = "",
    sigAlg = TlsHandshake.sigRsaPssRsaSha256,
    now = 0,
    sigAlgs = []
  } : TlsServer.serverConfig

  fun run () =
    let
      (* =============================================================== *)
      val () = section "HRR: synthetic-message transcript substitution (4.4.1)"
      val (cst0, ch1Record) = TlsClient.startHandshake (clientCfg ())
      val ch1Body = hsBody ch1Record
      val ch1Msg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ClientHello, body = ch1Body}

      val sst0 = TlsServer.receiveClientHello ch1Body
      val (sst1, hrrRecord) = TlsServer.produceHelloRetryRequest
        (sst0, serverCfg (),
         {group = TlsHandshake.groupSecp256r1, cookie = "retry-cookie-42"})

      (* The client processes the HRR and emits ClientHello2. *)
      val (cst1, cstOut) = TlsClient.step (cst0, hrrRecord)
      val () = checkBool "HRR: client emits exactly one CH2 record"
        (true, List.length cstOut = 1)
      val () = checkBool "HRR: client not in error after HRR"
        (true, not (Option.isSome (TlsClient.error cst1)))

      (* The client's transcript now begins with the synthetic message_hash
         message: type 254, 3-byte len 0x000020, then SHA-256(CH1). *)
      val synthetic = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.MessageHash, body = Sha256.digest ch1Msg}
      val () = checkBool "HRR: transcript begins with message_hash synthetic msg"
        (true, String.isPrefix synthetic (TlsClient.transcript cst1))
      val () = checkBytes ("HRR: synthetic msg header is fe 00 00 20",
        bytes [254, 0, 0, 32], String.substring (synthetic, 0, 4))

      (* =============================================================== *)
      val () = section "HRR: cookie echoed in ClientHello2"
      val ch2Record = List.hd cstOut
      val ch2Body = hsBody ch2Record
      val ch2 = Option.valOf (TlsHandshake.decodeClientHello ch2Body)
      val cookieData =
        case List.find (fn {extType, ...} => extType = TlsHandshake.extCookie)
                       (#extensions ch2) of
            SOME {data, ...} => TlsExtensions.decodeCookie data
          | NONE => NONE
      val () = checkBool "HRR: CH2 carries echoed cookie"
        (true, cookieData = SOME "retry-cookie-42")
      (* CH2 offers a secp256r1 key_share. *)
      val ch2Shares =
        case List.find (fn {extType, ...} => extType = TlsHandshake.extKeyShare)
                       (#extensions ch2) of
            SOME {data, ...} => Option.getOpt (TlsExtensions.decodeKeyShareCH data, [])
          | NONE => []
      val () = checkBool "HRR: CH2 key_share is secp256r1"
        (true, List.exists (fn {group, ...} => group = TlsHandshake.groupSecp256r1)
                           ch2Shares)

      (* =============================================================== *)
      val () = section "HRR: successful retry handshake (P-256)"
      val sst2 = TlsServer.receiveSecondClientHello (sst1, ch2Body)
      val (sst3, shRecord) = TlsServer.produceServerHello (sst2, serverCfg ())
      val (cst2, _) = TlsClient.step (cst1, shRecord)
      val () = checkBool "HRR: client negotiated AES-128-GCM after retry"
        (true, TlsClient.negotiatedCipherSuite cst2
                 = SOME TlsHandshake.suiteTlsAes128GcmSha256)
      val (sst4, flight) = TlsServer.produceServerFlight (sst3, serverCfg ())
      val (cst3, clientOut) = TlsClient.step (cst2, flight)
      val () = checkBool "HRR: client connected after retry handshake"
        (true, TlsClient.isConnected cst3)
      val (sst5, _) = TlsServer.step (sst4, List.hd clientOut)
      val () = checkBool "HRR: server connected after retry handshake"
        (true, TlsServer.isConnected sst5)
      val () = checkBool "HRR: both sides agree on server app key"
        (true, TlsServer.serverAppKey sst5 = TlsClient.serverAppKey cst3)
      val () = checkBool "HRR: both sides agree on client app key"
        (true, TlsServer.clientAppKey sst5 = TlsClient.clientAppKey cst3)

      (* =============================================================== *)
      val () = section "HRR: server-selected group already offered -> illegal_parameter"
      val (xcst0, xch1) = TlsClient.startHandshake (clientCfg ())
      val xsst0 = TlsServer.receiveClientHello (hsBody xch1)
      (* Server (incorrectly) asks the client to retry with X25519, a group
         the client already sent a key_share for. The client MUST abort. *)
      val (_, xhrr) = TlsServer.produceHelloRetryRequest
        (xsst0, serverCfg (), {group = TlsHandshake.groupX25519, cookie = ""})
      val (xcst1, _) = TlsClient.step (xcst0, xhrr)
      val () = checkBool "HRR: retry on already-offered group -> illegal_parameter"
        (true, alertIs (TlsClient.error xcst1, TlsAlert.IllegalParameter))

      (* =============================================================== *)
      val () = section "HRR: second HelloRetryRequest -> unexpected_message"
      val (ycst0, ych1) = TlsClient.startHandshake (clientCfg ())
      val ysst0 = TlsServer.receiveClientHello (hsBody ych1)
      val (ysst1, yhrr) = TlsServer.produceHelloRetryRequest
        (ysst0, serverCfg (), {group = TlsHandshake.groupSecp256r1, cookie = ""})
      val (ycst1, _) = TlsClient.step (ycst0, yhrr)
      (* A second HRR (same magic random) must be rejected. *)
      val (_, yhrr2) = TlsServer.produceHelloRetryRequest
        (ysst1, serverCfg (), {group = TlsHandshake.groupSecp256r1, cookie = ""})
      val (ycst2, _) = TlsClient.step (ycst1, yhrr2)
      val () = checkBool "HRR: second HRR -> unexpected_message"
        (true, alertIs (TlsClient.error ycst2, TlsAlert.UnexpectedMessage))

      (* =============================================================== *)
      (* 0-RTT / early_data reject (no PSK accept path)                  *)
      (* =============================================================== *)
      val () = section "early_data: server rejects offered 0-RTT"
      val earlyDataExt = {extType = TlsHandshake.extEarlyData, data = ""}
        : TlsClient.extension
      val edClientCfg = {
        x25519PrivateKey = clientX25519, p256PrivateKey = NONE,
        clientRandom = clientRandom, legacySessionId = "",
        cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
        extensions = [earlyDataExt], serverName = "example.com",
        trustStore = [], now = 0, sigAlgs = [TlsHandshake.sigRsaPssRsaSha256]
      } : TlsClient.clientConfig
      val edServerCfg = {
        x25519PrivateKey = serverX25519, p256PrivateKey = NONE,
        serverRandom = serverRandom,
        cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacySessionId = "", extensions = [], certChain = [],
        rsaPrivateKeyDer = "", sigAlg = TlsHandshake.sigRsaPssRsaSha256,
        now = 0, sigAlgs = []
      } : TlsServer.serverConfig

      val (ecst0, ech) = TlsClient.startHandshake edClientCfg
      val esst0 = TlsServer.receiveClientHello (hsBody ech)
      val (esst1, esh) = TlsServer.produceServerHello (esst0, edServerCfg)
      val (ecst1, _) = TlsClient.step (ecst0, esh)
      val (esst2, eflight) = TlsServer.produceServerFlight (esst1, edServerCfg)

      (* The server's EncryptedExtensions must NOT echo early_data: that
         omission is the reject signal (§4.2.10). *)
      val (shsK, shsIv) = Option.valOf (TlsServer.serverHandshakeKey esst1)
      val eeProt = TlsRecordProtect.init {key = shsK, iv = shsIv}
      val eeHasEarlyData =
        case TlsRecord.decodeCiphertext eflight of
            SOME (crec, _) =>
              (case TlsRecordProtect.unprotect
                      {state = eeProt, record = #encryptedRecord crec} of
                   SOME (TlsRecord.Handshake, pt, _) =>
                     (case TlsHandshake.decodeMessage pt of
                          SOME ({msgType = TlsHandshake.EncryptedExtensions, body}, _) =>
                            (case TlsHandshake.decodeEncryptedExtensions body of
                                 SOME exts =>
                                   List.exists (fn {extType, ...} =>
                                     extType = TlsHandshake.extEarlyData) exts
                               | NONE => true)
                        | _ => true)
                 | _ => true)
          | NONE => true
      val () = checkBool "early_data: EncryptedExtensions omits early_data"
        (true, not eeHasEarlyData)

      (* The 1-RTT handshake still completes despite the rejected 0-RTT. *)
      val (ecst2, eClientOut) = TlsClient.step (ecst1, eflight)
      val () = checkBool "early_data: client connects after reject"
        (true, TlsClient.isConnected ecst2)
      val finishedRecord = List.hd eClientOut

      (* Server skips undecryptable 0-RTT records that precede the client
         Finished, then connects. *)
      val () = section "early_data: server skips rejected 0-RTT records"
      val bogus0Rtt = TlsRecord.encodeCiphertext
        {contentType = TlsRecord.ApplicationData,
         encryptedRecord = bytes (List.tabulate (40, fn i => (i * 3) mod 256))}
      val (esst3, _) = TlsServer.step (esst2, bogus0Rtt ^ finishedRecord)
      val () = checkBool "early_data: server connects, skipping 0-RTT record"
        (true, TlsServer.isConnected esst3)

      (* Server handles an EndOfEarlyData message (skipped) before Finished. *)
      val () = section "early_data: server handles end_of_early_data"
      val (chsK, chsIv) = Option.valOf (TlsClient.clientHandshakeKey ecst1)
      val finPlain =
        case TlsRecordProtect.unprotect
               {state = TlsRecordProtect.init {key = chsK, iv = chsIv},
                record = (case TlsRecord.decodeCiphertext finishedRecord of
                              SOME (r, _) => #encryptedRecord r
                            | NONE => raise Fail "finishedRecord")} of
            SOME (_, pt, _) => pt
          | NONE => raise Fail "decrypt client Finished"
      val eoedMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.EndOfEarlyData, body = ""}
      val prot0 = TlsRecordProtect.init {key = chsK, iv = chsIv}
      val (eoedBody, prot1) = TlsRecordProtect.protect
        {state = prot0, innerType = TlsRecord.Handshake, plaintext = eoedMsg, pad = 0}
      val (finBody2, _) = TlsRecordProtect.protect
        {state = prot1, innerType = TlsRecord.Handshake, plaintext = finPlain, pad = 0}
      val eoedFlight =
        TlsRecord.encodeCiphertext
          {contentType = TlsRecord.ApplicationData, encryptedRecord = eoedBody}
        ^ TlsRecord.encodeCiphertext
          {contentType = TlsRecord.ApplicationData, encryptedRecord = finBody2}
      val (esst3b, _) = TlsServer.step (esst2, eoedFlight)
      val () = checkBool "early_data: server connects after end_of_early_data"
        (true, TlsServer.isConnected esst3b)

      (* Negative: with NO early_data offered, an undecryptable record is a
         genuine MAC failure -> bad_record_mac. *)
      val () = section "early_data: bogus record without offer -> bad_record_mac"
      val nClientCfg = {
        x25519PrivateKey = clientX25519, p256PrivateKey = NONE,
        clientRandom = clientRandom, legacySessionId = "",
        cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
        extensions = [], serverName = "example.com",
        trustStore = [], now = 0, sigAlgs = [TlsHandshake.sigRsaPssRsaSha256]
      } : TlsClient.clientConfig
      val (ncst0, nch) = TlsClient.startHandshake nClientCfg
      val nsst0 = TlsServer.receiveClientHello (hsBody nch)
      val (nsst1, nsh) = TlsServer.produceServerHello (nsst0, edServerCfg)
      val (ncst1, _) = TlsClient.step (ncst0, nsh)
      val (nsst2, _) = TlsServer.produceServerFlight (nsst1, edServerCfg)
      val (nsstErr, _) = TlsServer.step (nsst2, bogus0Rtt)
      val () = checkBool "early_data: bogus record (no offer) -> bad_record_mac"
        (true, alertIs (TlsServer.error nsstErr, TlsAlert.BadRecordMac))

      (* =============================================================== *)
      (* PSK resumption: spec-correct codecs + binder MAC (§4.2.11),     *)
      (* with an explicit server REJECT path (no PSK accept).            *)
      (* =============================================================== *)
      val () = section "PSK: resumption secret derivation (7.1)"
      val resMaster = TlsKeySchedule.resumptionMasterSecret
        {masterSecret = pat (fn i => i + 99), transcript = ""}
      val psk = TlsKeySchedule.resumptionPsk
        {resumptionMasterSecret = resMaster, ticketNonce = bytes [0, 1]}
      val pskAgain = TlsKeySchedule.resumptionPsk
        {resumptionMasterSecret = resMaster, ticketNonce = bytes [0, 1]}
      val wrongPsk = TlsKeySchedule.resumptionPsk
        {resumptionMasterSecret = resMaster, ticketNonce = bytes [9, 9]}
      val () = checkBool "PSK: resumptionPsk deterministic" (true, psk = pskAgain)
      val () = checkBool "PSK: resumptionPsk is 32 bytes" (true, String.size psk = 32)
      val () = checkBool "PSK: different ticket nonce -> different PSK"
        (true, psk <> wrongPsk)

      val () = section "PSK: pre_shared_key + psk_key_exchange_modes codecs"
      val pskModesData = TlsExtensions.encodePskKeyExchangeModes
        [TlsExtensions.pskModeDheKe]
      val () = checkBool "PSK: psk_key_exchange_modes round-trips"
        (true, TlsExtensions.decodePskKeyExchangeModes pskModesData
                 = SOME [TlsExtensions.pskModeDheKe])
      val () = checkBool "PSK: selected_identity round-trips"
        (true, TlsExtensions.decodeSelectedIdentity
                 (TlsExtensions.encodeSelectedIdentity 0w0) = SOME 0w0)

      (* Build a ClientHello carrying pre_shared_key (last) with a correctly
         computed binder over the truncated transcript (§4.2.11.2). *)
      val () = section "PSK: binder MAC computed + validated (4.2.11)"
      val (pcst0, pchRec) = TlsClient.startHandshake nClientCfg
      val baseCh = Option.valOf (TlsHandshake.decodeClientHello (hsBody pchRec))
      fun mkCh exts = {
        legacyVersion = #legacyVersion baseCh, random = #random baseCh,
        legacySessionId = #legacySessionId baseCh,
        cipherSuites = #cipherSuites baseCh,
        legacyCompression = #legacyCompression baseCh,
        extensions = exts
      } : TlsHandshake.clientHello
      val pskModesExt = {extType = TlsHandshake.extPskKeyExchangeModes,
                         data = pskModesData} : TlsHandshake.extension
      val ticket = "opaque-session-ticket"
      val ids = [{identity = ticket, obfuscatedTicketAge = 0w0}]
      val identitiesEnc = TlsExtensions.encodeOfferedPsksIdentities ids
      val binderPlaceholder = String.implode (List.tabulate (32, fn _ => Char.chr 0))
      val binderStructLen = 2 + TlsExtensions.binderListLength [binderPlaceholder]
      (* Full CH with a placeholder binder (correct lengths). *)
      val pskExtPlaceholder = {extType = TlsHandshake.extPreSharedKey,
        data = identitiesEnc ^ TlsExtensions.encodeBinderList [binderPlaceholder]}
        : TlsHandshake.extension
      val chFullBody = TlsHandshake.encodeClientHello
        (mkCh (#extensions baseCh @ [pskModesExt, pskExtPlaceholder]))
      val chFullMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ClientHello, body = chFullBody}
      (* Truncate(ClientHello): everything up to (excluding) the binders. *)
      val truncated = String.substring (chFullMsg, 0,
                        String.size chFullMsg - binderStructLen)
      val clientBinder = TlsKeySchedule.pskBinder {psk = psk, transcript = truncated}
      val pskExtReal = {extType = TlsHandshake.extPreSharedKey,
        data = identitiesEnc ^ TlsExtensions.encodeBinderList [clientBinder]}
        : TlsHandshake.extension
      val chRealBody = TlsHandshake.encodeClientHello
        (mkCh (#extensions baseCh @ [pskModesExt, pskExtReal]))
      val chRealMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ClientHello, body = chRealBody}

      (* Server-side: recompute the binder over the truncated received CH
         with the matching PSK -- it MUST equal the client's binder. *)
      val srvTruncated = String.substring (chRealMsg, 0,
                           String.size chRealMsg - binderStructLen)
      val serverBinder = TlsKeySchedule.pskBinder {psk = psk, transcript = srvTruncated}
      val () = checkBool "PSK: server recomputes the same binder (valid)"
        (true, serverBinder = clientBinder)
      val badBinder = TlsKeySchedule.pskBinder {psk = wrongPsk, transcript = srvTruncated}
      val () = checkBool "PSK: wrong PSK -> binder mismatch (would reject)"
        (true, badBinder <> clientBinder)
      (* The OfferedPsks body round-trips through the decoder. *)
      val () = checkBool "PSK: OfferedPsks identities+binder decode"
        (true, case TlsExtensions.decodeOfferedPsks (#data pskExtReal) of
                   SOME (ids', binders') =>
                     List.map #identity ids' = [ticket]
                     andalso binders' = [clientBinder]
                 | NONE => false)

      (* Explicit REJECT: a server given a ClientHello offering pre_shared_key
         does not select it -- the ServerHello omits pre_shared_key and the
         server falls back to a full (EC)DHE 1-RTT handshake. *)
      val () = section "PSK: server rejects the offered PSK (full 1-RTT)"
      val psst0 = TlsServer.receiveClientHello chRealBody
      val (psst1, pshRec) = TlsServer.produceServerHello (psst0, edServerCfg)
      val psh = Option.valOf (TlsHandshake.decodeServerHello (hsBody pshRec))
      val shHasPsk = List.exists
        (fn {extType, ...} => extType = TlsHandshake.extPreSharedKey)
        (#extensions psh)
      val () = checkBool "PSK: ServerHello omits pre_shared_key (rejected)"
        (true, not shHasPsk)
      val () = checkBool "PSK: server derived (EC)DHE handshake key (full 1-RTT)"
        (true, Option.isSome (TlsServer.serverHandshakeKey psst1))
    in
      ()
    end
end
