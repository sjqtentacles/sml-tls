(* Tests for sml-tls.

   The key-schedule and HKDF-Expand-Label vectors are from RFC 8448
   (Appendix A of RFC 8448), which provides a complete 1-RTT TLS 1.3
   handshake trace using X25519 and AES-128-GCM. We verify byte-for-byte
   against the published hex values; all hex strings here are decoded to
   raw bytes before comparison. *)

structure TlsTests =
struct
  open Harness

  (* ---- Hex helpers ----
     RFC 8448 publishes vectors as hex; we decode to raw bytes for
     comparison, since the library works in raw byte strings. *)
  fun nib c =
    if c >= #"0" andalso c <= #"9" then Char.ord c - Char.ord #"0"
    else if c >= #"a" andalso c <= #"f" then Char.ord c - Char.ord #"a" + 10
    else if c >= #"A" andalso c <= #"F" then Char.ord c - Char.ord #"A" + 10
    else ~1

  fun fromHex s =
    let
      (* Collapse whitespace (spaces/newlines) so multi-line hex blocks work. *)
      fun isSpace c = c = #" " orelse c = #"\n" orelse c = #"\t" orelse c = #"\r"
      val cleaned = String.implode (List.filter (not o isSpace) (String.explode s))
      val n = String.size cleaned
      fun loop (i, acc) =
        if i >= n then String.implode (List.rev acc)
        else
          let
            val hi = nib (String.sub (cleaned, i))
            val lo = if i + 1 < n then nib (String.sub (cleaned, i + 1)) else 0
          in
            if hi < 0 orelse lo < 0 then raise Fail "bad hex"
            else loop (i + 2, Char.chr (hi * 16 + lo) :: acc)
          end
    in
      loop (0, [])
    end

  (* Raw bytes -> lowercase hex, for error messages. *)
  fun toHex s =
    let
      fun one c =
        let val v = Char.ord c
            val h = v div 16 and l = v mod 16
            fun d n = if n < 10 then Char.chr (Char.ord #"0" + n)
                      else Char.chr (Char.ord #"a" + n - 10)
        in String.implode [d h, d l] end
    in String.concat (List.map one (String.explode s)) end

  fun bytesEq (a, b) = String.size a = String.size b andalso a = b

  (* Build a short byte string from small integer byte values. *)
  fun bytes [] = ""
    | bytes (n :: ns) = String.str (Char.chr n) ^ bytes ns

  (* A 2-byte string [a, b]. *)
  fun str2 a b = bytes [a, b]

  fun checkBytes (name, expected, actual) =
    if bytesEq (expected, actual) then check name true
    else
      let val () = print ("  FAIL - " ^ name ^ ": " ^ toHex expected ^ " <> " ^ toHex actual ^ "\n")
      in check name false end

  (* =================================================================== *)
  (* RFC 8448 key-schedule vectors                                        *)
  (* =================================================================== *)

  (* The ECDHE shared secret from RFC 8448 §A.1 (the X25519 output). *)
  val dhe = fromHex
    "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d\
    \35 e6 d6 6f 5e 79 39 76 f3 b5 d8 c7 70 41 33 0a"

  (* The 32-byte zero PSK (no PSK in this 1-RTT example). *)
  val pskZero = String.implode (List.tabulate (32, fn _ => #"\000"))

  (* Early secret = HKDF-Extract(0, PSK=0). From RFC 8448. *)
  val expectedEarlySecret = fromHex
    "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2\
    \10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"

  (* derived(early) = HKDF-Expand-Label(early, "derived", "", 32) *)
  val expectedDerivedEarly = fromHex
    "6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97\
    \16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba"

  (* handshake_secret = HKDF-Extract(derived(early), DHE). *)
  val expectedHandshakeSecret = fromHex
    "06 04 ad e0 37 f0 17 19 f2 6b 40 16 82 b8 ad f9\
    \64 6f a6 7a 20 9d 5c b3 d1 53 d6 3f fe 86 a3 95"

  (* derived(handshake) *)
  val expectedDerivedHandshake = fromHex
    "09 b4 ff d6 43 c7 3e e9 d2 01 45 98 00 7b 1c 18\
    \8e 4e 45 ba a1 1d 61 75 5e 3b db c6 b2 4c 2e fe"

  (* master_secret = HKDF-Extract(derived(handshake), 0). *)
  val expectedMasterSecret = fromHex
    "2d da 5d 74 5b 9b 75 6a 43 9b d7 69 19 17 e2 b6\
    \61 12 4b 63 a4 24 4d a9 24 c5 bd a2 f4 cd 49 6b"

  (* =================================================================== *)
  (* HKDF-Expand-Label test vector (RFC 8448)                            *)
  (* =================================================================== *)

  (* The "finished" key derived from the handshake secret's
     client-handshake-traffic secret. RFC 8448 gives:

       c_hs_traffic = DeriveSecret(handshake_secret, "c hs traffic", ...)
       finished_key = HKDF-Expand-Label(c_hs_traffic, "finished", "", 32)

     We instead test HKDF-Expand-Label directly against a simpler known
     pair: derived(early_secret) above, which is
       HKDF-Expand-Label(early, "derived", Hash(""), 32)
     where Hash("") is SHA-256 of the empty string. *)

  fun sha256Empty () = Sha256.digest ""

  fun run () =
    let
      val () = section "key schedule: early secret"

      val earlySecret = TlsKeySchedule.earlySecret {psk = pskZero}
      val () = checkBytes ("early_secret = HKDF-Extract(0, 0)",
                           expectedEarlySecret, earlySecret)

      val () = section "key schedule: derived(early)"
      val derivedEarly = TlsKeySchedule.hkdfExpandLabel {
        secret = earlySecret, label = "derived",
        context = sha256Empty (), length = 32
      }
      val () = checkBytes ("derived(early) = HKDF-Expand-Label(early, \"derived\", Hash(\"\"), 32)",
                           expectedDerivedEarly, derivedEarly)

      val () = section "key schedule: handshake secret"
      val handshakeSecret =
        TlsKeySchedule.handshakeSecret {earlySecret = earlySecret, dhe = dhe}
      val () = checkBytes ("handshake_secret = HKDF-Extract(derived(early), DHE)",
                           expectedHandshakeSecret, handshakeSecret)

      val () = section "key schedule: derived(handshake)"
      val derivedHandshake = TlsKeySchedule.hkdfExpandLabel {
        secret = handshakeSecret, label = "derived",
        context = sha256Empty (), length = 32
      }
      val () = checkBytes ("derived(handshake)",
                           expectedDerivedHandshake, derivedHandshake)

      val () = section "key schedule: master secret"
      val masterSecret =
        TlsKeySchedule.masterSecret {handshakeSecret = handshakeSecret}
      val () = checkBytes ("master_secret = HKDF-Extract(derived(handshake), 0)",
                           expectedMasterSecret, masterSecret)

      (* ---- Record layer round-trip ---- *)
      val () = section "record layer: TLSPlaintext round-trip"

      (* A trivial Handshake record with a 4-byte fragment. *)
      val frag = String.implode [#"A", #"B", #"C", #"D"]
      val pt = {contentType = TlsRecord.Handshake, fragment = frag}
      val enc = TlsRecord.encodePlaintext pt
      val dec = TlsRecord.decodePlaintext enc
      val () = case dec of
                   SOME (r, "") =>
                     (checkBool "plaintext content type" (true,
                        #contentType r = TlsRecord.Handshake);
                      checkBytes ("plaintext fragment", frag, #fragment r))
                 | _ => checkBool "plaintext decoded" (true, false)

      val () = section "record layer: TLSCiphertext round-trip"
      val cipher = {contentType = TlsRecord.ApplicationData,
                    encryptedRecord = String.implode [#"X", #"Y", #"Z"]}
      val cenc = TlsRecord.encodeCiphertext cipher
      val cdec = TlsRecord.decodeCiphertext cenc
      val () = case cdec of
                   SOME (r, "") =>
                     (checkBool ("ciphertext content type") (true,
                        #contentType r = TlsRecord.ApplicationData);
                      checkBytes ("ciphertext record",
                        #encryptedRecord cipher, #encryptedRecord r))
                 | _ => checkBool "ciphertext decoded" (true, false)

      (* Multiple records in a stream: decodePlaintext returns trailing
         bytes so the caller can parse a stream. *)
      val () = section "record layer: stream of two records"
      val two = TlsRecord.encodePlaintext pt
            ^ TlsRecord.encodePlaintext {contentType = TlsRecord.Alert,
                                         fragment = str2 1 0}
      val () = case TlsRecord.decodePlaintext two of
                   SOME (r1, rest) =>
                     (checkBool ("first record type") (true,
                        #contentType r1 = TlsRecord.Handshake);
                      case TlsRecord.decodePlaintext rest of
                          SOME (r2, "") =>
                            checkBool ("second record type") (true,
                              #contentType r2 = TlsRecord.Alert)
                        | _ => checkBool "second record parsed" (true, false))
                 | _ => checkBool "stream parsed" (true, false)

      (* ---- Alert round-trip ---- *)
      val () = section "alert: encode/decode round-trip"
      val a = {level = TlsAlert.Fatal, description = TlsAlert.HandshakeFailure}
      val aenc = TlsAlert.encode a
      val () = checkBytes ("alert is 2 bytes", str2 2 40, aenc)
      val () = case TlsAlert.decode aenc of
                   SOME r =>
                     (checkBool ("alert level") (true, #level r = TlsAlert.Fatal);
                      checkBool ("alert description") (true,
                        #description r = TlsAlert.HandshakeFailure))
                 | NONE => checkBool "alert decoded" (true, false)

      val () = section "alert: close_notify"
      val cn = {level = TlsAlert.Warning, description = TlsAlert.CloseNotify}
      val cnenc = TlsAlert.encode cn
      val () = checkBytes ("close_notify bytes", str2 1 0, cnenc)
      val () = checkBool ("close_notify decodes")
        (true, TlsAlert.decode cnenc = SOME cn)

      val () = section "alert: round-trip Other description"
      val other = {level = TlsAlert.Fatal, description = TlsAlert.Other 0w199}
      val () = checkBool ("Other round-trips")
        (true, TlsAlert.decode (TlsAlert.encode other) = SOME other)

      (* ---- Handshake message framing ---- *)
      val () = section "handshake: message framing round-trip"
      val msg = {msgType = TlsHandshake.ClientHello, body = "hello body"}
      val menc = TlsHandshake.encodeMessage msg
      (* 1-byte type (1), 3-byte length (10), body. *)
      val () = checkInt ("handshake message length") (4 + 10, String.size menc)
      val () = case TlsHandshake.decodeMessage menc of
                   SOME (m, "") =>
                     (checkBool ("msg type") (true,
                        #msgType m = TlsHandshake.ClientHello);
                      checkBytes ("msg body", "hello body", #body m))
                 | _ => checkBool "message decoded" (true, false)

      (* ---- Extension framing ---- *)
      val () = section "handshake: extension framing round-trip"
      val exts = [{extType = 0wx0017, data = "abc"},
                  {extType = 0wx002B, data = ""}]
      val eenc = TlsHandshake.encodeExtensions exts
      val () = case TlsHandshake.decodeExtensions eenc of
                   SOME es =>
                     checkBool ("extensions round-trip") (true, es = exts)
                 | NONE => checkBool "extensions decoded" (true, false)

      (* ---- ClientHello serialization ---- *)
      val () = section "handshake: ClientHello encode/decode round-trip"
      val clientRandom = String.implode (List.tabulate (32, fn i =>
        Char.chr ((i * 7) mod 256)))
      val ch = {
        legacyVersion = 0wx0303,
        random = clientRandom,
        legacySessionId = "session-id-32-bytes-padding-xxxxxx",
        cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256,
                        TlsHandshake.suiteTlsChaCha20Poly1305],
        legacyCompression = [0w0],
        extensions = [{extType = 0wx002B,
                       data = bytes [2, 3, 4]}]
      } : TlsHandshake.clientHello
      val chEnc = TlsHandshake.encodeClientHello ch
      val () = case TlsHandshake.decodeClientHello chEnc of
                   NONE => checkBool "ClientHello round-trip" (true, false)
                 | SOME ch' =>
                     (checkBool ("ClientHello version") (true,
                        #legacyVersion ch' = #legacyVersion ch);
                      checkBytes ("ClientHello random",
                        #random ch, #random ch');
                      checkBool ("ClientHello cipher suites") (true,
                        #cipherSuites ch' = #cipherSuites ch))

      (* ---- ServerHello serialization ---- *)
      val () = section "handshake: ServerHello encode/decode round-trip"
      val serverRandom = String.implode (List.tabulate (32, fn i =>
        Char.chr ((i * 11 + 5) mod 256)))
      val sh = {
        legacyVersion = 0wx0303,
        random = serverRandom,
        legacySessionId = "session-id-32-bytes-padding-xxxxxx",
        cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacyCompression = 0w0,
        extensions = [{extType = 0wx002B, data = bytes [3, 4]}]
      } : TlsHandshake.serverHello
      val shEnc = TlsHandshake.encodeServerHello sh
      val () = case TlsHandshake.decodeServerHello shEnc of
                   NONE => checkBool "ServerHello round-trip" (true, false)
                 | SOME sh' =>
                     (checkBool ("ServerHello version") (true,
                        #legacyVersion sh' = #legacyVersion sh);
                      checkBytes ("ServerHello random",
                        #random sh, #random sh');
                      checkBool ("ServerHello cipher suite") (true,
                        #cipherSuite sh' = #cipherSuite sh))

      (* ---- Certificate encode/decode ---- *)
      val () = section "handshake: Certificate encode/decode round-trip"
      val cert = {
        certificateRequestContext = "",
        certificateList = [
          {certData = "fake-cert-der-bytes", extensions = []},
          {certData = "another-cert", extensions =
             [{extType = 0wx0001, data = "x"}]}
        ]
      } : TlsHandshake.certificate
      val certEnc = TlsHandshake.encodeCertificate cert
      val () = case TlsHandshake.decodeCertificate certEnc of
                   NONE => checkBool "Certificate round-trip" (true, false)
                 | SOME cert' =>
                     checkBool ("Certificate list length") (true,
                       List.length (#certificateList cert') = 2)

      (* ---- CertificateVerify encode/decode ---- *)
      val () = section "handshake: CertificateVerify encode/decode round-trip"
      val cv = {sigAlg = TlsHandshake.sigRsaPssRsaSha256,
                sigBytes = "fake-signature-bytes"} : TlsHandshake.certificateVerify
      val cvEnc = TlsHandshake.encodeCertificateVerify cv
      val () = case TlsHandshake.decodeCertificateVerify cvEnc of
                   NONE => checkBool "CertificateVerify round-trip" (true, false)
                 | SOME cv' =>
                     (checkBool ("CertificateVerify sigAlg") (true,
                        #sigAlg cv' = #sigAlg cv);
                      checkBytes ("CertificateVerify sigBytes",
                        #sigBytes cv, #sigBytes cv'))

      (* ---- Finished encode/decode ---- *)
      val () = section "handshake: Finished encode/decode round-trip"
      val fin = {verifyData = "verify-data-bytes"} : TlsHandshake.finished
      val finEnc = TlsHandshake.encodeFinished fin
      val () = case TlsHandshake.decodeFinished finEnc of
                   NONE => checkBool "Finished round-trip" (true, false)
                 | SOME fin' =>
                     checkBytes ("Finished verifyData",
                       #verifyData fin, #verifyData fin')

      (* ---- NewSessionTicket encode/decode ---- *)
      val () = section "handshake: NewSessionTicket encode/decode round-trip"
      val nst = {
        ticketLifetime = 0wx00015180,
        ticketAgeAdd = 0wxFEDCBA98,
        ticketNonce = "nonce",
        ticket = "ticket-value",
        extensions = []
      } : TlsHandshake.newSessionTicket
      val nstEnc = TlsHandshake.encodeNewSessionTicket nst
      val () = case TlsHandshake.decodeNewSessionTicket nstEnc of
                   NONE => checkBool "NewSessionTicket round-trip" (true, false)
                 | SOME nst' =>
                     (checkBool ("NST lifetime") (true,
                        #ticketLifetime nst' = #ticketLifetime nst);
                      checkBytes ("NST ticket", #ticket nst, #ticket nst'))

      (* ---- Full key schedule from a fresh DHE ---- *)
      val () = section "key schedule: full schedule from DHE"
      val sched = TlsKeySchedule.schedule {
        dhe = dhe,
        handshakeTranscript = "",    (* empty transcript for this test *)
        applicationTranscript = ""
      }
      val () = checkBytes ("schedule.earlySecret",
        expectedEarlySecret, #earlySecret sched)
      val () = checkBytes ("schedule.handshakeSecret",
        expectedHandshakeSecret, #handshakeSecret sched)
      val () = checkBytes ("schedule.masterSecret",
        expectedMasterSecret, #masterSecret sched)

      (* ---- TlsClient: startHandshake produces a ClientHello record ---- *)
      val () = section "client: startHandshake"
      val clientPriv = String.implode (List.tabulate (32, fn i =>
        Char.chr ((i + 1) mod 256)))
      val clientCfg = {
        x25519PrivateKey = clientPriv,
        p256PrivateKey = NONE,
        clientRandom = clientRandom,
        legacySessionId = "",
        cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
        extensions = [],
        serverName = "example.com",
        trustStore = [],
        now = 0,
        sigAlgs = []
      } : TlsClient.clientConfig
      val (cst0, chRecord) = TlsClient.startHandshake clientCfg
      val () = checkBool ("startHandshake returns bytes") (true, chRecord <> "")
      val () = checkBool ("client not connected") (true, not (TlsClient.isConnected cst0))
      val () = case TlsRecord.decodePlaintext chRecord of
                   SOME (r, "") =>
                     checkBool ("record is handshake") (true,
                       #contentType r = TlsRecord.Handshake)
                 | _ => checkBool "record parses" (true, false)

      (* =============================================================== *)
      (* J1 integration: client <-> server full handshake + post-handshake *)
      (* =============================================================== *)

      (* Pull the handshake-message body out of a plaintext record. *)
      fun hsBody record =
        case TlsRecord.decodePlaintext record of
            SOME (r, _) =>
              (case TlsHandshake.decodeMessage (#fragment r) of
                   SOME ({body, ...}, _) => body
                 | _ => raise Fail "hsBody: no handshake message")
          | _ => raise Fail "hsBody: not a plaintext record"

      (* Pull the AEAD-protected body out of a ciphertext record. *)
      fun ctBody record =
        case TlsRecord.decodeCiphertext record of
            SOME (r, _) => #encryptedRecord r
          | NONE => raise Fail "ctBody: not a ciphertext record"

      val serverPriv = String.implode (List.tabulate (32, fn i =>
        Char.chr ((i * 7 + 3) mod 256)))
      val serverCfg = {
        x25519PrivateKey = serverPriv,
        p256PrivateKey = NONE,
        serverRandom = serverRandom,
        cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacySessionId = "",
        extensions = [],
        certChain = [],
        rsaPrivateKeyDer = "",
        sigAlg = TlsHandshake.sigRsaPssRsaSha256,
        now = 0,
        sigAlgs = []
      } : TlsServer.serverConfig

      (* ---- J1: full 1-RTT handshake (capstone) ---- *)
      val () = section "J1: client/server full 1-RTT handshake"
      val sst0 = TlsServer.receiveClientHello (hsBody chRecord)
      val (sst1, shRecord) = TlsServer.produceServerHello (sst0, serverCfg)
      val (cst1, _) = TlsClient.step (cst0, shRecord)
      val () = checkBool ("client negotiated suite")
        (true, TlsClient.negotiatedCipherSuite cst1
                 = SOME TlsHandshake.suiteTlsAes128GcmSha256)
      val (sst2, flight) = TlsServer.produceServerFlight (sst1, serverCfg)
      val (cst2, clientOut) = TlsClient.step (cst1, flight)
      val () = checkBool ("client connected after server flight")
        (true, TlsClient.isConnected cst2)
      val () = checkBool ("client emits one Finished record")
        (true, List.length clientOut = 1)
      val (sst3, _) = TlsServer.step (sst2, List.hd clientOut)
      val () = checkBool ("server connected after client Finished")
        (true, TlsServer.isConnected sst3)
      (* Both sides agreed on the same application-traffic keys. *)
      val () = checkBool ("server/client agree on server app key")
        (true, TlsServer.serverAppKey sst3 = TlsClient.serverAppKey cst2)
      val () = checkBool ("server/client agree on client app key")
        (true, TlsServer.clientAppKey sst3 = TlsClient.clientAppKey cst2)

      (* ---- J1: application data round-trip + sequence numbers ---- *)
      val () = section "J1: application data + incrementing sequence numbers"
      val (cst3, appRec0) = TlsClient.sendApplicationData (cst2, "message one")
      val (cst4, appRec1) = TlsClient.sendApplicationData (cst3, "message two")
      val () = checkBool ("two app records use different nonces (ciphertext differs)")
        (true, appRec0 <> appRec1)
      (* Decrypt them with the server's view of the client app key, in order. *)
      val (cak, caiv) = Option.valOf (TlsClient.clientAppKey cst2)
      val rd0 = TlsRecordProtect.init {key = cak, iv = caiv}
      val () = case TlsRecordProtect.unprotect {state = rd0, record = ctBody appRec0} of
                   SOME (_, pt, rd1) =>
                     (checkBytes ("record 0 (seq 0) decrypts", "message one", pt);
                      case TlsRecordProtect.unprotect {state = rd1, record = ctBody appRec1} of
                          SOME (_, pt2, _) =>
                            checkBytes ("record 1 (seq 1) decrypts", "message two", pt2)
                        | NONE => checkBool "record 1 decrypts" (true, false))
                 | NONE => checkBool "record 0 decrypts" (true, false)

      (* ---- J1: KeyUpdate rekeys the client application traffic key ---- *)
      val () = section "J1: KeyUpdate rekey"
      val (cstK, kuRec) = TlsClient.requestKeyUpdate cst2
      val () = checkBool ("client app key changes after KeyUpdate")
        (true, TlsClient.clientAppKey cstK <> TlsClient.clientAppKey cst2)
      val (sstK, _) = TlsServer.step (sst3, kuRec)
      val () = checkBool ("server rekeys client-read after KeyUpdate")
        (true, TlsServer.clientAppKey sstK = TlsClient.clientAppKey cstK)
      val (_, appRecK) = TlsClient.sendApplicationData (cstK, "after rekey")
      val (nck, nciv) = Option.valOf (TlsClient.clientAppKey cstK)
      val rdK = TlsRecordProtect.init {key = nck, iv = nciv}
      val () = case TlsRecordProtect.unprotect {state = rdK, record = ctBody appRecK} of
                   SOME (_, pt, _) => checkBytes ("app data under new key", "after rekey", pt)
                 | NONE => checkBool "app data under new key" (true, false)

      (* ---- J1: NewSessionTicket issuance round-trip ---- *)
      val () = section "J1: NewSessionTicket round-trip"
      val nst = {
        ticketLifetime = 0w7200,
        ticketAgeAdd = 0w12345,
        ticketNonce = bytes [0, 1],
        ticket = "opaque-session-ticket",
        extensions = []
      } : TlsHandshake.newSessionTicket
      val nstBody = TlsHandshake.encodeNewSessionTicket nst
      val (_, nstRec) = TlsServer.produceNewSessionTicket (sst3, serverCfg, nstBody)
      val (sak, saiv) = Option.valOf (TlsServer.serverAppKey sst3)
      val rdN = TlsRecordProtect.init {key = sak, iv = saiv}
      val () = case TlsRecordProtect.unprotect {state = rdN, record = ctBody nstRec} of
                   SOME (TlsRecord.Handshake, pt, _) =>
                     (case TlsHandshake.decodeMessage pt of
                          SOME ({msgType = TlsHandshake.NewSessionTicket, body}, _) =>
                            (case TlsHandshake.decodeNewSessionTicket body of
                                 SOME nst' =>
                                   checkBytes ("NST ticket round-trips",
                                     "opaque-session-ticket", #ticket nst')
                               | NONE => checkBool "NST decodes" (true, false))
                        | _ => checkBool "NST message type" (true, false))
                 | _ => checkBool "NST record decrypts as handshake" (true, false)

      (* ---- J1: ServerHello cipher-suite mismatch -> illegal_parameter ---- *)
      val () = section "J1: ServerHello suite mismatch -> illegal_parameter"
      val badSuiteCfg = {
        x25519PrivateKey = serverPriv, p256PrivateKey = NONE,
        serverRandom = serverRandom,
        cipherSuite = TlsHandshake.suiteTlsAes256GcmSha384,  (* not offered *)
        legacySessionId = "", extensions = [], certChain = [],
        rsaPrivateKeyDer = "", sigAlg = TlsHandshake.sigRsaPssRsaSha256,
        now = 0, sigAlgs = []
      } : TlsServer.serverConfig
      val (bSst, badSuiteSh) =
        TlsServer.produceServerHello (TlsServer.receiveClientHello (hsBody chRecord), badSuiteCfg)
      val (cstBad, _) = TlsClient.step (cst0, badSuiteSh)
      val () = checkBool ("suite mismatch -> illegal_parameter")
        (true, TlsClient.error cstBad
                 = SOME (TlsAlert.alertDescriptionToByte TlsAlert.IllegalParameter))
      val () = checkBool ("client not connected after suite mismatch")
        (true, not (TlsClient.isConnected cstBad))

      (* ---- J1: downgrade sentinel in ServerHello.random -> illegal_parameter ---- *)
      val () = section "J1: downgrade sentinel -> illegal_parameter"
      val dgRandom =
        String.substring (serverRandom, 0, 24) ^ TlsExtensions.downgradeSentinelTls12
      val dgCfg = {
        x25519PrivateKey = serverPriv, p256PrivateKey = NONE,
        serverRandom = dgRandom,
        cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacySessionId = "", extensions = [], certChain = [],
        rsaPrivateKeyDer = "", sigAlg = TlsHandshake.sigRsaPssRsaSha256,
        now = 0, sigAlgs = []
      } : TlsServer.serverConfig
      val (_, dgSh) =
        TlsServer.produceServerHello (TlsServer.receiveClientHello (hsBody chRecord), dgCfg)
      val (cstDg, _) = TlsClient.step (cst0, dgSh)
      val () = checkBool ("downgrade sentinel -> illegal_parameter")
        (true, TlsClient.error cstDg
                 = SOME (TlsAlert.alertDescriptionToByte TlsAlert.IllegalParameter))

      (* ---- J1: ServerHello selected_version != TLS 1.3 -> protocol_version ---- *)
      val () = section "J1: version mismatch -> protocol_version"
      val verSh = {
        legacyVersion = 0wx0303, random = serverRandom, legacySessionId = "",
        cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacyCompression = 0w0,
        extensions = [
          {extType = TlsHandshake.extSupportedVersions,
           data = TlsHandshake.word16ToBytes 0wx0303}  (* TLS 1.2, not 1.3 *)
        ]
      } : TlsHandshake.serverHello
      val verShRec = TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake,
         fragment = TlsHandshake.encodeMessage
           {msgType = TlsHandshake.ServerHello,
            body = TlsHandshake.encodeServerHello verSh}}
      val (cstVer, _) = TlsClient.step (cst0, verShRec)
      val () = checkBool ("version mismatch -> protocol_version")
        (true, TlsClient.error cstVer
                 = SOME (TlsAlert.alertDescriptionToByte TlsAlert.ProtocolVersion))

      (* ---- J1: certificate verification wired at the Certificate step ---- *)
      val () = section "J1: certificate verification rejects a bad chain"
      val trustingCfg = {
        x25519PrivateKey = clientPriv, p256PrivateKey = NONE,
        clientRandom = clientRandom, legacySessionId = "",
        cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
        extensions = [], serverName = "example.com",
        trustStore = ["not-a-real-anchor"],   (* forces verifyChain to run *)
        now = 0, sigAlgs = []
      } : TlsClient.clientConfig
      val (tcst0, tchRecord) = TlsClient.startHandshake trustingCfg
      val badCertServerCfg = {
        x25519PrivateKey = serverPriv, p256PrivateKey = NONE,
        serverRandom = serverRandom,
        cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
        legacySessionId = "", extensions = [],
        certChain = ["bogus-leaf-der"],        (* will not verify *)
        rsaPrivateKeyDer = "", sigAlg = TlsHandshake.sigRsaPssRsaSha256,
        now = 0, sigAlgs = []
      } : TlsServer.serverConfig
      val tsst0 = TlsServer.receiveClientHello (hsBody tchRecord)
      val (tsst1, tShRecord) = TlsServer.produceServerHello (tsst0, badCertServerCfg)
      val (tcst1, _) = TlsClient.step (tcst0, tShRecord)
      val (tsst2, tFlight) = TlsServer.produceServerFlight (tsst1, badCertServerCfg)
      val (tcstErr, _) = TlsClient.step (tcst1, tFlight)
      val () = checkBool ("bad chain -> client error set")
        (true, Option.isSome (TlsClient.error tcstErr))
      val () = checkBool ("bad chain -> client not connected")
        (true, not (TlsClient.isConnected tcstErr))
    in
      ()
    end
end
