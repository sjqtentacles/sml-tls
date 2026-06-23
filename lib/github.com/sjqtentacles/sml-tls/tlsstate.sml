(* tlsstate.sml

   The TLS 1.3 handshake state machine (TlsClient / TlsServer) and the
   bundled `Tls` structure. Split out of tls.sml at the J1 join so it can
   load AFTER the parallel-track modules it integrates: TlsRecordProtect
   (A1, record AEAD), TlsCertVerify (A2, chain validation), TlsExtensions
   (A3, extension codecs), and P256 (A4, ECDHE/ECDSA). Those modules in
   turn depend on the early TLS structures (TlsRecord / TlsAlert /
   TlsHandshake / TlsKeySchedule) which remain in tls.sml. *)

structure TlsClient :> TLS_CLIENT =
struct
  exception Tls of string

  type extension = {extType : Word16.word, data : string}

  type clientConfig = {
    x25519PrivateKey  : string,
    p256PrivateKey    : string option,
    clientRandom      : string,
    legacySessionId   : string,
    cipherSuites      : Word16.word list,
    extensions        : extension list,
    serverName        : string,
    trustStore        : string list,
    now               : int,
    sigAlgs           : Word16.word list
  }

  (* The opaque state carries everything the client learns during the
     handshake: config (trust store / hostname / clock for cert
     validation), private key, transcript-so-far, negotiated parameters,
     derived secrets, traffic keys, and the per-direction record-protection
     states (which own the AEAD sequence counters). *)
  type clientState = {
    config            : clientConfig,
    x25519PrivateKey  : Secret.secret,
    clientHello       : TlsHandshake.clientHello,
    transcript        : string,
    cipherSuite       : Word16.word option,
    dhe               : Secret.secret,
    negotiatedGroup   : Word16.word option,
    serverHello       : TlsHandshake.serverHello option,
    clientHsSecret    : Secret.secret option,
    serverHsSecret    : Secret.secret option,
    clientApSecret    : Secret.secret option,
    serverApSecret    : Secret.secret option,
    serverHandshakeKey : (Secret.secret * Secret.secret) option,
    clientHandshakeKey : (Secret.secret * Secret.secret) option,
    serverAppKey : (Secret.secret * Secret.secret) option,
    clientAppKey : (Secret.secret * Secret.secret) option,
    serverHsProtect   : TlsRecordProtect.state option,  (* read: server HS *)
    serverApProtect   : TlsRecordProtect.state option,  (* read: server app *)
    clientApProtect   : TlsRecordProtect.state option,  (* write: client app *)
    certVerified      : bool,
    errorAlert        : Word8.word option,
    connected         : bool
  }

  (* Map a negotiated cipher suite to its AEAD algorithm + key/iv lengths. *)
  fun suiteAlg cs =
    if cs = TlsHandshake.suiteTlsAes128GcmSha256 then Aead.AesGcm128
    else if cs = TlsHandshake.suiteTlsAes256GcmSha384 then Aead.AesGcm256
    else if cs = TlsHandshake.suiteTlsChaCha20Poly1305 then Aead.ChaCha20Poly1305
    else Aead.AesGcm128

  fun suiteKeyIvLen cs =
    if cs = TlsHandshake.suiteTlsAes256GcmSha384 then (32, 12) else (16, 12)

  fun mkProtect (cs, (key, iv)) =
    TlsRecordProtect.initWithAlg {key = key, iv = iv, alg = suiteAlg cs}

  (* RFC 8446 §5.2: a received TLSCiphertext.length MUST NOT exceed
     2^14 + 256; otherwise the receiver MUST send record_overflow. This is
     a cheap pre-decrypt DoS bound. *)
  val maxCiphertextLen = 16384 + 256

  fun alertByte d = TlsAlert.alertDescriptionToByte d

  (* Local fatal-alert signal, caught in `step` and mapped to a terminal
     error state + an Alert record. *)
  exception Fatal of TlsAlert.alertDescription

  (* Build the key_share extension for X25519: the client's public key. *)
  fun keyShareExtension (privKey : string) : TlsHandshake.extension =
    let
      val pubKey = X25519.base privKey
      (* key_share ClientHello entry: 2-byte named group, 2-byte key length,
         key bytes. *)
      val entry = TlsHandshake.word16ToBytes TlsHandshake.groupX25519
        ^ TlsHandshake.word16ToBytes (Word16.fromInt (String.size pubKey))
        ^ pubKey
      (* The extension data is a 2-byte length-prefixed list of entries. *)
      val data = TlsHandshake.word16ToBytes (Word16.fromInt (String.size entry)) ^ entry
    in
      {extType = TlsHandshake.extKeyShare, data = data}
    end

  (* Build the supported_versions extension for a ClientHello: a 1-byte
     length prefix then a list of 2-byte versions, here just 0x0304 (TLS 1.3). *)
  fun supportedVersionsExtension () : TlsHandshake.extension =
    let
      val tls13 = 0wx0304
      val data = String.str (Char.chr 2) ^ TlsHandshake.word16ToBytes tls13
    in
      {extType = TlsHandshake.extSupportedVersions, data = data}
    end

  (* Build a supported_groups extension: 2-byte length, then list of 2-byte
     named groups. *)
  fun supportedGroupsExtension () : TlsHandshake.extension =
    let
      val groups = [TlsHandshake.groupX25519]
      val body = String.concat (List.map TlsHandshake.word16ToBytes groups)
      val data = TlsHandshake.word16ToBytes (Word16.fromInt (String.size body)) ^ body
    in
      {extType = TlsHandshake.extSupportedGroups, data = data}
    end

  (* Build a signature_algorithms extension: 2-byte length, then list of
     2-byte scheme codes. *)
  fun signatureAlgorithmsExtension () : TlsHandshake.extension =
    let
      val algs = [TlsHandshake.sigRsaPssRsaSha256,
                  TlsHandshake.sigRsaPssRsaSha384,
                  TlsHandshake.sigRsaPssRsaSha512]
      val body = String.concat (List.map TlsHandshake.word16ToBytes algs)
      val data = TlsHandshake.word16ToBytes (Word16.fromInt (String.size body)) ^ body
    in
      {extType = TlsHandshake.extSignatureAlgorithms, data = data}
    end

  (* Build the ClientHello key_share extension. We offer a single X25519
     key_share by default (the preferred group); when a P-256 key is also
     configured we still advertise secp256r1 in supported_groups but do NOT
     send a P-256 share up front. This is spec-legal (RFC 8446 §4.2.8: a
     client need not send a share for every advertised group) and lets the
     server force a P-256 retry via HelloRetryRequest. *)
  fun keyShareEntriesFor (group, cfg : clientConfig) : TlsExtensions.keyShareEntry =
    if group = TlsHandshake.groupX25519 then
      {group = TlsHandshake.groupX25519,
       keyExchange = X25519.base (#x25519PrivateKey cfg)}
    else (* secp256r1 *)
      (case #p256PrivateKey cfg of
           SOME pk => {group = TlsHandshake.groupSecp256r1,
                       keyExchange = P256.generatePublic pk}
         | NONE => raise Tls "keyShareEntriesFor: no P-256 key")

  fun keyShareExtensionMulti (cfg : clientConfig) : TlsHandshake.extension =
    {extType = TlsHandshake.extKeyShare,
     data = TlsExtensions.encodeKeyShareCH
              [keyShareEntriesFor (TlsHandshake.groupX25519, cfg)]}

  fun supportedGroupsExtensionMulti (cfg : clientConfig) : TlsHandshake.extension =
    let
      val groups =
        case #p256PrivateKey cfg of
            SOME _ => [TlsHandshake.groupX25519, TlsHandshake.groupSecp256r1]
          | NONE => [TlsHandshake.groupX25519]
    in
      {extType = TlsHandshake.extSupportedGroups,
       data = TlsExtensions.encodeSupportedGroups groups}
    end

  (* Build a ClientHello offering a single `keyShareGroup` key_share, while
     still advertising every supported group. `cookieOpt` is SOME when this
     is ClientHello2 in response to a HelloRetryRequest (the cookie is
     echoed verbatim, §4.2.2). *)
  fun buildClientHello (cfg : clientConfig, keyShareGroup, cookieOpt)
      : TlsHandshake.clientHello =
    let
      val keyShare =
        {extType = TlsHandshake.extKeyShare,
         data = TlsExtensions.encodeKeyShareCH
                  [keyShareEntriesFor (keyShareGroup, cfg)]}
      val supVer = supportedVersionsExtension ()
      val supGrp = supportedGroupsExtensionMulti cfg
      val sigAlg = signatureAlgorithmsExtension ()
      val sni =
        if #serverName cfg = "" then []
        else [{extType = TlsHandshake.extServerName,
               data = TlsExtensions.encodeServerName (#serverName cfg)}
              : TlsHandshake.extension]
      val cookie =
        case cookieOpt of
            SOME c => [{extType = TlsHandshake.extCookie,
                        data = TlsExtensions.encodeCookie c}
                       : TlsHandshake.extension]
          | NONE => []
      val allExts =
        List.concat [#extensions cfg, [keyShare, supVer, supGrp, sigAlg],
                     sni, cookie]
    in
      {
        legacyVersion = 0wx0303,
        random = #clientRandom cfg,
        legacySessionId = #legacySessionId cfg,
        cipherSuites = #cipherSuites cfg,
        legacyCompression = [0w0],
        extensions = allExts
      }
    end

  fun startHandshake (cfg : clientConfig) : clientState * string =
    let
      val ch = buildClientHello (cfg, TlsHandshake.groupX25519, NONE)
      val body = TlsHandshake.encodeClientHello ch
      val msg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ClientHello, body = body}
      val record = TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake, fragment = msg}
      val st = {
        config = cfg,
        x25519PrivateKey = Secret.fromString (#x25519PrivateKey cfg),
        clientHello = ch,
        transcript = msg,
        cipherSuite = NONE,
        dhe = Secret.empty,
        negotiatedGroup = NONE,
        serverHello = NONE,
        clientHsSecret = NONE,
        serverHsSecret = NONE,
        clientApSecret = NONE,
        serverApSecret = NONE,
        serverHandshakeKey = NONE,
        clientHandshakeKey = NONE,
        serverAppKey = NONE,
        clientAppKey = NONE,
        serverHsProtect = NONE,
        serverApProtect = NONE,
        clientApProtect = NONE,
        certVerified = false,
        errorAlert = NONE,
        connected = false
      } : clientState
    in
      (st, record)
    end

  (* Find an extension by type in a ServerHello's extension list. *)
  fun findExt (exts : TlsHandshake.extension list, ty) =
    case List.find (fn {extType, ...} => extType = ty) exts of
        SOME {data, ...} => SOME data
      | NONE => NONE

  (* Extract the server's selected key_share (group + key) via A3's codec. *)
  fun serverKeyShareEntry (sh : TlsHandshake.serverHello) =
    case findExt (#extensions sh, TlsHandshake.extKeyShare) of
        NONE => NONE
      | SOME data => TlsExtensions.decodeKeyShareSH data

  (* Compute the ECDHE shared secret for the negotiated group. *)
  fun computeDhe (st : clientState, group, peerPub) =
    if group = TlsHandshake.groupX25519 then
      (* X25519 public keys are always exactly 32 bytes (RFC 7748); reject
         any other length rather than crashing X25519.dh. *)
      (if String.size peerPub = 32
       then SOME (X25519.dh (Secret.toBytes (#x25519PrivateKey st)) peerPub)
       else NONE)
    else if group = TlsHandshake.groupSecp256r1 then
      (case #p256PrivateKey (#config st) of
           SOME pk => P256.ecdh {privateKey = pk, peerPublic = peerPub}
         | NONE => NONE)
    else NONE

  (* After receiving ServerHello: enforce negotiated parameters (version,
     cipher suite, group), check the downgrade sentinel, compute the ECDHE
     shared secret, and derive the handshake-traffic keys.  Protocol
     violations raise `Fatal alert`. *)
  fun processServerHello (st : clientState, shBody : string) : clientState =
    case TlsHandshake.decodeServerHello shBody of
        NONE => raise Fatal TlsAlert.DecodeError
      | SOME sh =>
          let
            (* Illegal legacy fields (RFC 8446 §4.1.3): legacy_version MUST
               be 0x0303 and legacy_compression_method MUST be 0; a client
               receiving anything else MUST abort with illegal_parameter. *)
            val () =
              if #legacyVersion sh = 0wx0303 then ()
              else raise Fatal TlsAlert.IllegalParameter
            val () =
              if #legacyCompression sh = 0w0 then ()
              else raise Fatal TlsAlert.IllegalParameter
            val cs = #cipherSuite sh
            (* Enforce: cipher suite must be one the client offered. *)
            val () =
              if List.exists (fn c => c = cs) (#cipherSuites (#clientHello st))
              then () else raise Fatal TlsAlert.IllegalParameter
            (* Downgrade-protection sentinel (§4.1.3): last 8 bytes of the
               ServerHello.random must not be the TLS 1.2 / 1.1 sentinels. *)
            val rnd = #random sh
            val () =
              if String.size rnd >= 8 then
                let val tail = String.substring (rnd, String.size rnd - 8, 8) in
                  if tail = TlsExtensions.downgradeSentinelTls12 orelse
                     tail = TlsExtensions.downgradeSentinelTls11
                  then raise Fatal TlsAlert.IllegalParameter else ()
                end
              else ()
            (* Enforce: selected_version (supported_versions SH) must be
               TLS 1.3 (0x0304). *)
            val () =
              case findExt (#extensions sh, TlsHandshake.extSupportedVersions) of
                  SOME data =>
                    (case TlsExtensions.decodeSelectedVersionSH data of
                         SOME v => if v = 0wx0304 then ()
                                   else raise Fatal TlsAlert.ProtocolVersion
                       | NONE => raise Fatal TlsAlert.DecodeError)
                | NONE => raise Fatal TlsAlert.MissingExtension
            (* key_share: parse the server's selected group + peer key, and
               enforce that the group is one the client actually offered. *)
            val (group, peerPub) =
              case serverKeyShareEntry sh of
                  NONE => raise Fatal TlsAlert.MissingExtension
                | SOME {group, keyExchange} =>
                    let
                      val offered =
                        group = TlsHandshake.groupX25519 orelse
                        (group = TlsHandshake.groupSecp256r1 andalso
                         Option.isSome (#p256PrivateKey (#config st)))
                    in
                      if offered then (group, keyExchange)
                      else raise Fatal TlsAlert.IllegalParameter
                    end
            val dhe =
              case computeDhe (st, group, peerPub) of
                  SOME d => d
                | NONE => raise Fatal TlsAlert.IllegalParameter
            val shMsg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.ServerHello, body = shBody}
            val transcript = #transcript st ^ shMsg
            val sched = TlsKeySchedule.schedule {
              dhe = dhe,
              handshakeTranscript = transcript,
              applicationTranscript = ""
            }
            val (keyLen, ivLen) = suiteKeyIvLen cs
            (* Materialize each derived secret/key/iv into ONE mutable,
               reference-shared Secret. The same Secret object is stored in
               the state field AND handed to the record-protection state, so a
               single in-place wipe at teardown erases both views. *)
            val cHsSec = Secret.fromString (#clientHandshakeSecret sched)
            val sHsSec = Secret.fromString (#serverHandshakeSecret sched)
            val sHsKey = Secret.fromString (TlsKeySchedule.trafficKey
              {secret = #serverHandshakeSecret sched, keyLength = keyLen})
            val sHsIv = Secret.fromString (TlsKeySchedule.trafficIv
              {secret = #serverHandshakeSecret sched, ivLength = ivLen})
            val cHsKey = Secret.fromString (TlsKeySchedule.trafficKey
              {secret = #clientHandshakeSecret sched, keyLength = keyLen})
            val cHsIv = Secret.fromString (TlsKeySchedule.trafficIv
              {secret = #clientHandshakeSecret sched, ivLength = ivLen})
          in
            { config = #config st,
              x25519PrivateKey = #x25519PrivateKey st,
              clientHello = #clientHello st,
              transcript = transcript,
              cipherSuite = SOME cs,
              dhe = Secret.fromString dhe,
              negotiatedGroup = SOME group,
              serverHello = SOME sh,
              clientHsSecret = SOME cHsSec,
              serverHsSecret = SOME sHsSec,
              clientApSecret = NONE,
              serverApSecret = NONE,
              serverHandshakeKey = SOME (sHsKey, sHsIv),
              clientHandshakeKey = SOME (cHsKey, cHsIv),
              serverAppKey = NONE,
              clientAppKey = NONE,
              serverHsProtect = SOME (mkProtect (cs, (sHsKey, sHsIv))),
              serverApProtect = NONE,
              clientApProtect = NONE,
              certVerified = false,
              errorAlert = NONE,
              connected = false }
          end

  (* Process an incoming HelloRetryRequest (RFC 8446 §4.1.4): validate the
     server's `selected_group`, apply the synthetic-message transcript
     substitution (§4.4.1: ClientHello1 is replaced by
       message_hash || 00 00 Hash.length || Hash(ClientHello1)),
     then resend ClientHello2 with the requested key_share and the echoed
     cookie. Returns the new state and the CH2 record to send. *)
  fun processHelloRetryRequest (st : clientState, shBody : string)
      : clientState * string list =
    case TlsHandshake.decodeServerHello shBody of
        NONE => raise Fatal TlsAlert.DecodeError
      | SOME sh =>
          let
            (* A second HelloRetryRequest is illegal (§4.1.4). After the
               first HRR the transcript begins with the synthetic
               message_hash message (handshake type 254). *)
            val () =
              if String.size (#transcript st) > 0 andalso
                 String.sub (#transcript st, 0) = Char.chr 254
              then raise Fatal TlsAlert.UnexpectedMessage else ()
            (* selected_version must be TLS 1.3. *)
            val () =
              case findExt (#extensions sh, TlsHandshake.extSupportedVersions) of
                  SOME data =>
                    (case TlsExtensions.decodeSelectedVersionSH data of
                         SOME v => if v = 0wx0304 then ()
                                   else raise Fatal TlsAlert.ProtocolVersion
                       | NONE => raise Fatal TlsAlert.DecodeError)
                | NONE => raise Fatal TlsAlert.MissingExtension
            (* The HRR key_share carries only the server's selected_group. *)
            val group =
              case findExt (#extensions sh, TlsHandshake.extKeyShare) of
                  NONE => raise Fatal TlsAlert.MissingExtension
                | SOME data =>
                    (case TlsExtensions.decodeKeyShareHRR data of
                         SOME g => g
                       | NONE => raise Fatal TlsAlert.DecodeError)
            (* The selected group must be one the client advertised but did
               NOT already send a key_share for. The client only ever sends
               an X25519 share up front, so a HRR selecting X25519 (which we
               already offered) is illegal (§4.1.4). A secp256r1 retry is
               valid only when a P-256 key is configured. *)
            val () =
              if group = TlsHandshake.groupSecp256r1 andalso
                 Option.isSome (#p256PrivateKey (#config st))
              then ()
              else raise Fatal TlsAlert.IllegalParameter
            (* Echo the cookie verbatim if the server sent one. *)
            val cookieOpt =
              case findExt (#extensions sh, TlsHandshake.extCookie) of
                  NONE => NONE
                | SOME data =>
                    (case TlsExtensions.decodeCookie data of
                         SOME c => SOME c
                       | NONE => raise Fatal TlsAlert.DecodeError)
            (* Synthetic-message transcript substitution (§4.4.1). *)
            val ch1Msg = #transcript st
            val synthetic = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.MessageHash,
               body = Sha256.digest ch1Msg}
            val hrrMsg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.ServerHello, body = shBody}
            val ch2 = buildClientHello (#config st, group, cookieOpt)
            val ch2Body = TlsHandshake.encodeClientHello ch2
            val ch2Msg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.ClientHello, body = ch2Body}
            val newTranscript = synthetic ^ hrrMsg ^ ch2Msg
            val record = TlsRecord.encodePlaintext
              {contentType = TlsRecord.Handshake, fragment = ch2Msg}
            val st' = {
              config = #config st,
              x25519PrivateKey = #x25519PrivateKey st,
              clientHello = ch2,
              transcript = newTranscript,
              cipherSuite = NONE,
              dhe = Secret.empty,
              negotiatedGroup = SOME group,
              serverHello = NONE,
              clientHsSecret = NONE,
              serverHsSecret = NONE,
              clientApSecret = NONE,
              serverApSecret = NONE,
              serverHandshakeKey = NONE,
              clientHandshakeKey = NONE,
              serverAppKey = NONE,
              clientAppKey = NONE,
              serverHsProtect = NONE,
              serverApProtect = NONE,
              clientApProtect = NONE,
              certVerified = false,
              errorAlert = NONE,
              connected = false
            } : clientState
          in
            (st', [record])
          end

  (* A fatal plaintext Alert record (used before traffic keys exist, and as
     a best-effort terminal signal). *)
  fun alertRecord desc =
    TlsRecord.encodePlaintext
      {contentType = TlsRecord.Alert,
       fragment = TlsAlert.encode {level = TlsAlert.Fatal, description = desc}}

  (* Transition the client into a terminal error state carrying `desc`. *)
  fun setError (st : clientState, desc) : clientState =
    { config = #config st, x25519PrivateKey = #x25519PrivateKey st,
      clientHello = #clientHello st, transcript = #transcript st,
      cipherSuite = #cipherSuite st, dhe = #dhe st,
      negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
      clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
      clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
      serverHandshakeKey = #serverHandshakeKey st,
      clientHandshakeKey = #clientHandshakeKey st,
      serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
      serverHsProtect = #serverHsProtect st, serverApProtect = #serverApProtect st,
      clientApProtect = #clientApProtect st, certVerified = #certVerified st,
      errorAlert = SOME (alertByte desc), connected = #connected st }

  (* The next application-traffic secret after a KeyUpdate (RFC 8446 §7.2):
     application_traffic_secret_N+1 =
       HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length) *)
  fun nextAppSecret secret =
    TlsKeySchedule.hkdfExpandLabel
      {secret = secret, label = "traffic upd", context = "",
       length = TlsKeySchedule.hashLen}

  (* Decrypt a sequence of ciphertext records under `prot`, skipping any
     ChangeCipherSpec records, returning the advanced protect-state and the
     concatenated inner plaintext (handshake bytes). *)
  fun decryptFlight (remaining, prot, acc) =
    if remaining = "" then (prot, acc)
    else
      case TlsRecord.decodeCiphertext remaining of
          NONE => raise Fatal TlsAlert.DecodeError
        | SOME (crec, rest) =>
            if #contentType crec = TlsRecord.ChangeCipherSpec then
              decryptFlight (rest, prot, acc)
            else if String.size (#encryptedRecord crec) > maxCiphertextLen then
              raise Fatal TlsAlert.RecordOverflow
            else
              (case TlsRecordProtect.unprotect
                      {state = prot, record = #encryptedRecord crec} of
                   NONE => raise Fatal TlsAlert.BadRecordMac
                 | SOME (_, pt, prot') =>
                     decryptFlight (rest, prot', acc ^ pt))

  (* Verify the server certificate chain at the Certificate step. Skipped
     when no trust anchors are configured (so handshakes can be exercised
     without a PKI in tests). *)
  fun verifyServerCert (st : clientState, certBody) =
    let val cfg = #config st in
      if null (#trustStore cfg) then ()
      else
        case TlsHandshake.decodeCertificate certBody of
            NONE => raise Fatal TlsAlert.DecodeError
          | SOME {certificateList, ...} =>
              let
                val chain = List.map #certData certificateList
                val result =
                  TlsCertVerify.verifyChain
                    {chain = chain, trust = #trustStore cfg,
                     hostname = #serverName cfg, now = #now cfg,
                     sigAlgs = #sigAlgs cfg}
                  handle _ => TlsCertVerify.Invalid TlsAlert.BadCertificate
              in
                case result of
                    TlsCertVerify.Valid => ()
                  | TlsCertVerify.Invalid desc => raise Fatal desc
              end
    end

  (* Process the decrypted server handshake flight (EncryptedExtensions,
     Certificate, CertificateVerify, Finished), threading the transcript.
     On the server Finished: verify its MAC, derive application-traffic
     keys, build the client Finished, and mark the connection connected. *)
  fun processFlight (st : clientState, hs : string) : clientState * string list =
    let
      val cs = Option.valOf (#cipherSuite st)
      val serverHsSecret = Secret.toBytes (Option.valOf (#serverHsSecret st))
      val clientHsSecret = Secret.toBytes (Option.valOf (#clientHsSecret st))
      val (keyLen, ivLen) = suiteKeyIvLen cs
      val offeredSigAlgs = #sigAlgs (#config st)
      fun loop (remaining, transcript, certOk, leafCert) =
        if remaining = "" then
          (* flight without a Finished: stay un-connected, just record. *)
          ({ config = #config st, x25519PrivateKey = #x25519PrivateKey st,
             clientHello = #clientHello st, transcript = transcript,
             cipherSuite = #cipherSuite st, dhe = #dhe st,
             negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
             clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
             clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
             serverHandshakeKey = #serverHandshakeKey st,
             clientHandshakeKey = #clientHandshakeKey st,
             serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
             serverHsProtect = #serverHsProtect st,
             serverApProtect = #serverApProtect st,
             clientApProtect = #clientApProtect st, certVerified = certOk,
             errorAlert = NONE, connected = false } : clientState, [])
        else
          case TlsHandshake.decodeMessage remaining of
              NONE => raise Fatal TlsAlert.DecodeError
            | SOME ({msgType, body}, rest) =>
                let
                  val msg = TlsHandshake.encodeMessage {msgType = msgType, body = body}
                  val transcript' = transcript ^ msg
                in
                  case msgType of
                      TlsHandshake.Certificate =>
                        let
                          (* Capture the leaf (first entry) so a later
                             CertificateVerify can be checked against it. *)
                          val leaf =
                            case TlsHandshake.decodeCertificate body of
                                SOME {certificateList = (e :: _), ...} =>
                                  SOME (#certData e)
                              | _ => NONE
                        in
                          verifyServerCert (st, body);
                          loop (rest, transcript', true, leaf)
                        end
                    | TlsHandshake.CertificateVerify =>
                        (case TlsHandshake.decodeCertificateVerify body of
                             NONE => raise Fatal TlsAlert.DecodeError
                           | SOME {sigAlg, sigBytes} =>
                               (* Gate real verification on a non-empty
                                  signature so legacy empty-sig handshakes
                                  (no server key configured) still pass. *)
                               if sigBytes = "" then
                                 loop (rest, transcript', certOk, leafCert)
                               else
                                 let
                                   (* (1) the CV scheme must be one the client
                                      offered in signature_algorithms. *)
                                   val () =
                                     if List.exists (fn a => a = sigAlg)
                                                    offeredSigAlgs
                                     then ()
                                     else raise Fatal TlsAlert.IllegalParameter
                                   (* (2) extract the leaf's RSA public key. *)
                                   val pub =
                                     case leafCert of
                                         NONE => raise Fatal TlsAlert.DecryptError
                                       | SOME der =>
                                           (case (X509.rsaPublicKey
                                                    (X509.parse der)
                                                  handle _ => NONE) of
                                                SOME p => p
                                              | NONE =>
                                                  raise Fatal
                                                    TlsAlert.BadCertificate)
                                   (* (3) verify the signature over the
                                      transcript hash THROUGH Certificate
                                      (i.e. the transcript before this CV). *)
                                   val ok =
                                     TlsKeySchedule.verifyServerCertVerify
                                       {pub = pub, sigAlg = sigAlg,
                                        transcript = transcript,
                                        sgn = sigBytes}
                                   val () =
                                     if ok then ()
                                     else raise Fatal TlsAlert.DecryptError
                                 in
                                   loop (rest, transcript', true, leafCert)
                                 end)
                    | TlsHandshake.Finished =>
                        let
                          (* Verify the server Finished MAC over the transcript
                             up to (not including) this Finished. *)
                          val sfKey = TlsKeySchedule.finishedKey {secret = serverHsSecret}
                          val expected = TlsKeySchedule.finishedVerifyData
                            {finishedKey = sfKey, transcript = transcript}
                          val () = if expected = body then ()
                                   else raise Fatal TlsAlert.DecryptError
                          (* Application-traffic keys from the transcript through
                             the server Finished. *)
                          val sched = TlsKeySchedule.schedule {
                            dhe = Secret.toBytes (#dhe st),
                            handshakeTranscript = #transcript st,
                            applicationTranscript = transcript'
                          }
                          val sApSecB = #serverAppSecret sched
                          val cApSecB = #clientAppSecret sched
                          val sApSec = Secret.fromString sApSecB
                          val cApSec = Secret.fromString cApSecB
                          val sApKey = Secret.fromString (TlsKeySchedule.trafficKey {secret = sApSecB, keyLength = keyLen})
                          val sApIv  = Secret.fromString (TlsKeySchedule.trafficIv  {secret = sApSecB, ivLength = ivLen})
                          val cApKey = Secret.fromString (TlsKeySchedule.trafficKey {secret = cApSecB, keyLength = keyLen})
                          val cApIv  = Secret.fromString (TlsKeySchedule.trafficIv  {secret = cApSecB, ivLength = ivLen})
                          (* Client Finished MAC over the transcript through the
                             server Finished. *)
                          val cfKey = TlsKeySchedule.finishedKey {secret = clientHsSecret}
                          val cfVerify = TlsKeySchedule.finishedVerifyData
                            {finishedKey = cfKey, transcript = transcript'}
                          val cfBody = TlsHandshake.encodeFinished {verifyData = cfVerify}
                          val cfMsg = TlsHandshake.encodeMessage
                            {msgType = TlsHandshake.Finished, body = cfBody}
                          (* Encrypt the client Finished under the client
                             handshake-traffic key (write seq starts at 0). *)
                          val cHsKiv = Option.valOf (#clientHandshakeKey st)
                          val cfProt = mkProtect (cs, cHsKiv)
                          val (cfRecBody, _) = TlsRecordProtect.protect
                            {state = cfProt, innerType = TlsRecord.Handshake,
                             plaintext = cfMsg, pad = 0}
                          val cfRecord = TlsRecord.encodeCiphertext
                            {contentType = TlsRecord.ApplicationData,
                             encryptedRecord = cfRecBody}
                          val st' = {
                            config = #config st, x25519PrivateKey = #x25519PrivateKey st,
                            clientHello = #clientHello st,
                            transcript = transcript' ^ cfMsg,
                            cipherSuite = #cipherSuite st, dhe = #dhe st,
                            negotiatedGroup = #negotiatedGroup st,
                            serverHello = #serverHello st,
                            clientHsSecret = #clientHsSecret st,
                            serverHsSecret = #serverHsSecret st,
                            clientApSecret = SOME cApSec, serverApSecret = SOME sApSec,
                            serverHandshakeKey = #serverHandshakeKey st,
                            clientHandshakeKey = #clientHandshakeKey st,
                            serverAppKey = SOME (sApKey, sApIv),
                            clientAppKey = SOME (cApKey, cApIv),
                            serverHsProtect = #serverHsProtect st,
                            serverApProtect = SOME (mkProtect (cs, (sApKey, sApIv))),
                            clientApProtect = SOME (mkProtect (cs, (cApKey, cApIv))),
                            certVerified = certOk, errorAlert = NONE,
                            connected = true } : clientState
                        in
                          (st', [cfRecord])
                        end
                    | _ => loop (rest, transcript', certOk, leafCert)
                end
    in
      loop (hs, #transcript st, #certVerified st, NONE)
    end

  (* Update just the server-app read protect-state. *)
  fun withServerApProtect (st : clientState, prot') : clientState =
    { config = #config st, x25519PrivateKey = #x25519PrivateKey st,
      clientHello = #clientHello st, transcript = #transcript st,
      cipherSuite = #cipherSuite st, dhe = #dhe st,
      negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
      clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
      clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
      serverHandshakeKey = #serverHandshakeKey st,
      clientHandshakeKey = #clientHandshakeKey st,
      serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
      serverHsProtect = #serverHsProtect st, serverApProtect = SOME prot',
      clientApProtect = #clientApProtect st, certVerified = #certVerified st,
      errorAlert = #errorAlert st, connected = #connected st }

  (* Rekey the server-app read side after an incoming KeyUpdate. *)
  fun rekeyServerRead (st : clientState) : clientState =
    let
      val cs = Option.valOf (#cipherSuite st)
      val (kl, il) = suiteKeyIvLen cs
      val next = nextAppSecret (Secret.toBytes (Option.valOf (#serverApSecret st)))
      val nextS = Secret.fromString next
      val k = Secret.fromString (TlsKeySchedule.trafficKey {secret = next, keyLength = kl})
      val iv = Secret.fromString (TlsKeySchedule.trafficIv {secret = next, ivLength = il})
    in
      { config = #config st, x25519PrivateKey = #x25519PrivateKey st,
        clientHello = #clientHello st, transcript = #transcript st,
        cipherSuite = #cipherSuite st, dhe = #dhe st,
        negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
        clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
        clientApSecret = #clientApSecret st, serverApSecret = SOME nextS,
        serverHandshakeKey = #serverHandshakeKey st,
        clientHandshakeKey = #clientHandshakeKey st,
        serverAppKey = SOME (k, iv), clientAppKey = #clientAppKey st,
        serverHsProtect = #serverHsProtect st,
        serverApProtect = SOME (mkProtect (cs, (k, iv))),
        clientApProtect = #clientApProtect st, certVerified = #certVerified st,
        errorAlert = #errorAlert st, connected = #connected st }
    end

  (* Handle records received once connected: application data is decrypted
     (and dropped, since `step` returns only bytes-to-send); a KeyUpdate
     rekeys the server-app read side (§7.2). *)
  fun stepConnected (st, input) =
    let
      fun loop (remaining, st0, outs) =
        if remaining = "" then (st0, List.rev outs)
        else
          case TlsRecord.decodeCiphertext remaining of
              NONE => raise Fatal TlsAlert.DecodeError
            | SOME (crec, rest) =>
                if #contentType crec = TlsRecord.ChangeCipherSpec then
                  loop (rest, st0, outs)
                else if String.size (#encryptedRecord crec) > maxCiphertextLen then
                  raise Fatal TlsAlert.RecordOverflow
                else
                  let val prot = Option.valOf (#serverApProtect st0) in
                    case TlsRecordProtect.unprotect
                           {state = prot, record = #encryptedRecord crec} of
                        NONE => raise Fatal TlsAlert.BadRecordMac
                      | SOME (innerCt, pt, prot') =>
                          let val st1 = withServerApProtect (st0, prot') in
                            case innerCt of
                                TlsRecord.Handshake =>
                                  (case TlsHandshake.decodeMessage pt of
                                       SOME ({msgType = TlsHandshake.KeyUpdate, ...}, _) =>
                                         loop (rest, rekeyServerRead st1, outs)
                                     | _ => loop (rest, st1, outs))
                              | _ => loop (rest, st1, outs)
                          end
                  end
    in
      loop (input, st, [])
    end

  fun step (st : clientState, input : string) : clientState * string list =
    if Option.isSome (#errorAlert st) then (st, [])
    else
      (case #serverHello st of
           NONE =>
             (* Expect a plaintext ServerHello record (or a bare ServerHello
                handshake message). `rest` holds any records the peer
                coalesced after the ServerHello (commonly a middlebox-compat
                ChangeCipherSpec plus the encrypted flight); we drain it in
                the same call so a single buffer drives the client through. *)
             let
               val (body, rest) =
                 case TlsRecord.decodePlaintext input of
                     SOME (r, rest) =>
                       if #contentType r = TlsRecord.Handshake
                       then (#fragment r, rest)
                       else (input, "")
                   | NONE => (input, "")
             in
               case TlsHandshake.decodeMessage body of
                   SOME ({msgType = TlsHandshake.ServerHello, body = shBody}, _) =>
                     (case TlsHandshake.decodeServerHello shBody of
                          NONE => raise Fatal TlsAlert.DecodeError
                        | SOME sh =>
                            if #random sh = TlsHandshake.helloRetryRequestRandom
                            then processHelloRetryRequest (st, shBody)
                            else
                              let val st' = processServerHello (st, shBody)
                              in
                                (* If the peer coalesced the encrypted flight
                                   into this buffer, keep processing it. *)
                                if rest = "" then (st', [])
                                else step (st', rest)
                              end)
                 | _ => raise Fatal TlsAlert.UnexpectedMessage
             end
         | SOME _ =>
             if not (#connected st) then
               let
                 val prot0 = Option.valOf (#serverHsProtect st)
                 val (_, hs) = decryptFlight (input, prot0, "")
               in
                 processFlight (st, hs)
               end
             else
               stepConnected (st, input))
      handle Fatal desc => (setError (st, desc), [alertRecord desc])
           (* Backstop: no malformed peer input may escape `step` as an
              uncaught exception. Anything unforeseen maps to a fatal
              decode_error and a terminal error state (never a crash). *)
           | _ => (setError (st, TlsAlert.DecodeError),
                   [alertRecord TlsAlert.DecodeError])

  (* Send application data under the client application-traffic key,
     threading the AEAD sequence counter through `clientApProtect`. *)
  fun sendApplicationData (st : clientState, data : string) : clientState * string =
    case #clientApProtect st of
        SOME prot =>
          let
            val (body, prot') = TlsRecordProtect.protect
              {state = prot, innerType = TlsRecord.ApplicationData,
               plaintext = data, pad = 0}
            val record = TlsRecord.encodeCiphertext
              {contentType = TlsRecord.ApplicationData, encryptedRecord = body}
            val st' = {
              config = #config st, x25519PrivateKey = #x25519PrivateKey st,
              clientHello = #clientHello st, transcript = #transcript st,
              cipherSuite = #cipherSuite st, dhe = #dhe st,
              negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
              clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
              clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
              serverHandshakeKey = #serverHandshakeKey st,
              clientHandshakeKey = #clientHandshakeKey st,
              serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
              serverHsProtect = #serverHsProtect st,
              serverApProtect = #serverApProtect st,
              clientApProtect = SOME prot', certVerified = #certVerified st,
              errorAlert = #errorAlert st, connected = #connected st } : clientState
          in
            (st', record)
          end
      | NONE => raise Tls "sendApplicationData: not connected"

  (* Request a key update (RFC 8446 §4.6.3 / §7.2): send a KeyUpdate under
     the CURRENT client-app key, then rekey the client-app write side. *)
  fun requestKeyUpdate (st : clientState) : clientState * string =
    case (#cipherSuite st, #clientApSecret st, #clientApProtect st) of
        (SOME cs, SOME secret, SOME prot) =>
          let
            val kuMsg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.KeyUpdate, body = String.str (Char.chr 0)}
            val (body, _) = TlsRecordProtect.protect
              {state = prot, innerType = TlsRecord.Handshake,
               plaintext = kuMsg, pad = 0}
            val record = TlsRecord.encodeCiphertext
              {contentType = TlsRecord.ApplicationData, encryptedRecord = body}
            val (kl, il) = suiteKeyIvLen cs
            val next = nextAppSecret (Secret.toBytes secret)
            val nextS = Secret.fromString next
            val k = Secret.fromString (TlsKeySchedule.trafficKey {secret = next, keyLength = kl})
            val iv = Secret.fromString (TlsKeySchedule.trafficIv {secret = next, ivLength = il})
            val st' = {
              config = #config st, x25519PrivateKey = #x25519PrivateKey st,
              clientHello = #clientHello st, transcript = #transcript st,
              cipherSuite = #cipherSuite st, dhe = #dhe st,
              negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
              clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
              clientApSecret = SOME nextS, serverApSecret = #serverApSecret st,
              serverHandshakeKey = #serverHandshakeKey st,
              clientHandshakeKey = #clientHandshakeKey st,
              serverAppKey = #serverAppKey st, clientAppKey = SOME (k, iv),
              serverHsProtect = #serverHsProtect st,
              serverApProtect = #serverApProtect st,
              clientApProtect = SOME (mkProtect (cs, (k, iv))),
              certVerified = #certVerified st, errorAlert = #errorAlert st,
              connected = #connected st } : clientState
          in
            (st', record)
          end
      | _ => raise Tls "requestKeyUpdate: not connected"

  fun error (st : clientState) : Word8.word option = #errorAlert st

  fun negotiatedCipherSuite (st : clientState) = #cipherSuite st
  local
    fun kivBytes NONE = NONE
      | kivBytes (SOME (k, iv)) = SOME (Secret.toBytes k, Secret.toBytes iv)
  in
    fun serverHandshakeKey (st : clientState) = kivBytes (#serverHandshakeKey st)
    fun clientHandshakeKey (st : clientState) = kivBytes (#clientHandshakeKey st)
    fun serverAppKey (st : clientState) = kivBytes (#serverAppKey st)
    fun clientAppKey (st : clientState) = kivBytes (#clientAppKey st)
  end
  fun transcript (st : clientState) = #transcript st
  fun isConnected (st : clientState) = #connected st

  fun certVerified (st : clientState) = #certVerified st

  (* ---- Track 1b: secure zeroing of client key material ---- *)
  (* Wipe every secret buffer the state holds IN PLACE (mutating the live,
     reference-shared Word8Array), then return the SAME state. Because the
     buffers are shared, the wipe is observable through every alias of the
     state -- including the original handle the caller passed in -- not just
     the returned value. This is the real in-place erasure the old
     rebind-to-zeros could not provide. *)
  local
    fun wOpt NONE = () | wOpt (SOME s) = Secret.wipe s
    fun wKey NONE = () | wKey (SOME (k, iv)) = (Secret.wipe k; Secret.wipe iv)
    (* Wipe the old record-protect state's key/iv buffers in place before we
       drop the reference (the `zProt` gap: the old key bytes used to leak). *)
    fun wProt NONE = () | wProt (SOME st) =
      (Secret.wipe (TlsRecordProtect.keySecret st);
       Secret.wipe (TlsRecordProtect.ivSecret st))
  in
    fun zeroize (st : clientState) : clientState =
      ( Secret.wipe (#x25519PrivateKey st)
      ; Secret.wipe (#dhe st)
      ; wOpt (#clientHsSecret st)
      ; wOpt (#serverHsSecret st)
      ; wOpt (#clientApSecret st)
      ; wOpt (#serverApSecret st)
      ; wKey (#serverHandshakeKey st)
      ; wKey (#clientHandshakeKey st)
      ; wKey (#serverAppKey st)
      ; wKey (#clientAppKey st)
      ; wProt (#serverHsProtect st)
      ; wProt (#serverApProtect st)
      ; wProt (#clientApProtect st)
      ; st )
  end

  fun secretsForTest (st : clientState) : string list =
    let
      fun ofKey NONE = [] | ofKey (SOME (k, iv)) = [Secret.toBytes k, Secret.toBytes iv]
      fun ofOpt NONE = [] | ofOpt (SOME s) = [Secret.toBytes s]
    in
      [Secret.toBytes (#x25519PrivateKey st), Secret.toBytes (#dhe st)]
      @ ofOpt (#clientHsSecret st) @ ofOpt (#serverHsSecret st)
      @ ofOpt (#clientApSecret st) @ ofOpt (#serverApSecret st)
      @ ofKey (#serverHandshakeKey st) @ ofKey (#clientHandshakeKey st)
      @ ofKey (#serverAppKey st) @ ofKey (#clientAppKey st)
    end

  (* The client's long-term key material lives in `clientConfig` (the X25519
     and optional P-256 private keys), not the per-connection state, so it is
     wiped separately. Config fields are caller-provided immutable strings, so
     this returns a config with those fields rebound to zeros (best-effort,
     same immutability caveat as the server `zeroizeConfig`). *)
  fun zeroizeConfig (cfg : clientConfig) : clientConfig =
    { x25519PrivateKey = SecureZero.zeroString (#x25519PrivateKey cfg),
      p256PrivateKey =
        (case #p256PrivateKey cfg of
             NONE => NONE
           | SOME s => SOME (SecureZero.zeroString s)),
      clientRandom = #clientRandom cfg,
      legacySessionId = #legacySessionId cfg,
      cipherSuites = #cipherSuites cfg,
      extensions = #extensions cfg,
      serverName = #serverName cfg,
      trustStore = #trustStore cfg,
      now = #now cfg,
      sigAlgs = #sigAlgs cfg }
end

structure TlsServer :> TLS_SERVER =
struct
  exception Tls of string

  type extension = {extType : Word16.word, data : string}

  type serverConfig = {
    x25519PrivateKey  : string,
    p256PrivateKey    : string option,
    serverRandom      : string,
    cipherSuite       : Word16.word,
    legacySessionId   : string,
    extensions        : extension list,
    certChain         : string list,
    rsaPrivateKeyDer  : string,
    sigAlg            : Word16.word,
    now               : int,
    sigAlgs           : Word16.word list
  }

  type serverState = {
    x25519PrivateKey  : Secret.secret,
    serverRandom      : string,
    cipherSuite       : Word16.word option,
    legacySessionId   : string,
    extensions        : TlsHandshake.extension list,
    transcript        : string,
    dhe               : Secret.secret,
    clientHello       : TlsHandshake.clientHello option,
    serverHello       : TlsHandshake.serverHello option,
    clientHsSecret    : Secret.secret option,
    serverHsSecret    : Secret.secret option,
    clientApSecret    : Secret.secret option,
    serverApSecret    : Secret.secret option,
    serverHandshakeKey : (Secret.secret * Secret.secret) option,
    clientHandshakeKey : (Secret.secret * Secret.secret) option,
    serverAppKey : (Secret.secret * Secret.secret) option,
    clientAppKey : (Secret.secret * Secret.secret) option,
    clientHsProtect   : TlsRecordProtect.state option,  (* read: client HS *)
    clientApProtect   : TlsRecordProtect.state option,  (* read: client app *)
    serverApProtect   : TlsRecordProtect.state option,  (* write: server app *)
    errorAlert        : Word8.word option,
    connected         : bool
  }

  (* Cipher-suite -> AEAD algorithm + key/iv lengths (mirrors TlsClient). *)
  fun suiteAlg cs =
    if cs = TlsHandshake.suiteTlsAes128GcmSha256 then Aead.AesGcm128
    else if cs = TlsHandshake.suiteTlsAes256GcmSha384 then Aead.AesGcm256
    else if cs = TlsHandshake.suiteTlsChaCha20Poly1305 then Aead.ChaCha20Poly1305
    else Aead.AesGcm128

  fun suiteKeyIvLen cs =
    if cs = TlsHandshake.suiteTlsAes256GcmSha384 then (32, 12) else (16, 12)

  fun mkProtect (cs, (key, iv)) =
    TlsRecordProtect.initWithAlg {key = key, iv = iv, alg = suiteAlg cs}

  (* ---- PSK resumption ticket store (Track 1c) ----
     An in-memory map from a ticket's opaque identity bytes to the
     resumption PSK derived from the issuing connection. Populated by
     produceNewSessionTicket and consulted by produceServerHello. A
     process-wide ref models a single server's session cache. *)
  val ticketStore : (string * Secret.secret) list ref = ref []

  (* Wipe every stored PSK buffer in place, then drop the entries. The PSKs
     are reference-shared Secret buffers, so this erases the live bytes before
     the list is cleared (teardown of the server session cache). *)
  fun clearTicketStore () =
    ( List.app (fn (_, psk) => Secret.wipe psk) (!ticketStore)
    ; ticketStore := [] )

  fun lookupTicket id =
    Option.map (Secret.toBytes o #2)
               (List.find (fn (k, _) => k = id) (!ticketStore))

  fun storeTicket (id, psk) =
    ticketStore := (id, Secret.fromString psk)
                   :: List.filter (fn (k, _) => k <> id) (!ticketStore)

  (* RFC 8446 §5.2 record_overflow bound (see TlsClient). *)
  val maxCiphertextLen = 16384 + 256

  fun nextAppSecret secret =
    TlsKeySchedule.hkdfExpandLabel
      {secret = secret, label = "traffic upd", context = "",
       length = TlsKeySchedule.hashLen}

  exception Fatal of TlsAlert.alertDescription

  fun alertRecord desc =
    TlsRecord.encodePlaintext
      {contentType = TlsRecord.Alert,
       fragment = TlsAlert.encode {level = TlsAlert.Fatal, description = desc}}

  fun setError (st : serverState, desc) : serverState =
    { x25519PrivateKey = #x25519PrivateKey st, serverRandom = #serverRandom st,
      cipherSuite = #cipherSuite st, legacySessionId = #legacySessionId st,
      extensions = #extensions st, transcript = #transcript st, dhe = #dhe st,
      clientHello = #clientHello st, serverHello = #serverHello st,
      clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
      clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
      serverHandshakeKey = #serverHandshakeKey st,
      clientHandshakeKey = #clientHandshakeKey st,
      serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
      clientHsProtect = #clientHsProtect st, clientApProtect = #clientApProtect st,
      serverApProtect = #serverApProtect st,
      errorAlert = SOME (TlsAlert.alertDescriptionToByte desc),
      connected = #connected st }

  fun receiveClientHello (chBody : string) : serverState =
    case TlsHandshake.decodeClientHello chBody of
        NONE => raise Tls "malformed ClientHello"
      | SOME ch =>
          let
            val chMsg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.ClientHello, body = chBody}
          in
            { x25519PrivateKey = Secret.empty,
              serverRandom = "",
              cipherSuite = NONE,
              legacySessionId = "",
              extensions = [],
              transcript = chMsg,
              dhe = Secret.empty,
              clientHello = SOME ch,
              serverHello = NONE,
              clientHsSecret = NONE,
              serverHsSecret = NONE,
              clientApSecret = NONE,
              serverApSecret = NONE,
              serverHandshakeKey = NONE,
              clientHandshakeKey = NONE,
              serverAppKey = NONE,
              clientAppKey = NONE,
              clientHsProtect = NONE,
              clientApProtect = NONE,
              serverApProtect = NONE,
              errorAlert = NONE,
              connected = false }
          end

  fun supportedVersionsServerExt () : TlsHandshake.extension =
    let
      val data = TlsHandshake.word16ToBytes 0wx0304
    in
      {extType = TlsHandshake.extSupportedVersions, data = data}
    end

  (* The groups this server supports, in preference order. X25519 is always
     available; secp256r1 only when a P-256 key is configured (A4). *)
  fun serverGroups (cfg : serverConfig) =
    case #p256PrivateKey cfg of
        SOME _ => [TlsHandshake.groupX25519, TlsHandshake.groupSecp256r1]
      | NONE => [TlsHandshake.groupX25519]

  (* Parse the client's key_share list from a ClientHello. *)
  fun clientKeyShares (ch : TlsHandshake.clientHello)
      : TlsExtensions.keyShareEntry list =
    case List.find (fn {extType, ...} => extType = TlsHandshake.extKeyShare)
                   (#extensions ch) of
        SOME {data, ...} =>
          (case TlsExtensions.decodeKeyShareCH data of
               SOME xs => xs
             | NONE => [])
      | NONE => []

  (* Compute (serverPublicKeyShare, dhe) for the negotiated group. *)
  fun serverShareAndDhe (cfg : serverConfig, group, peerPub) =
    if group = TlsHandshake.groupX25519 then
      (X25519.base (#x25519PrivateKey cfg), X25519.dh (#x25519PrivateKey cfg) peerPub)
    else (* secp256r1 *)
      (case #p256PrivateKey cfg of
           NONE => raise Tls "no P-256 key for negotiated group"
         | SOME pk =>
             (P256.generatePublic pk,
              case P256.ecdh {privateKey = pk, peerPublic = peerPub} of
                  SOME d => d
                | NONE => raise Tls "P-256 ECDH failed"))

  (* Build the server's ServerHello key_share extension for the chosen
     group + public key. *)
  fun serverKeyShareExt (group, pub) : TlsHandshake.extension =
    {extType = TlsHandshake.extKeyShare,
     data = TlsExtensions.encodeKeyShareSH {group = group, keyExchange = pub}}

  (* ---- PSK resumption selection (Track 1c, RFC 8446 §4.2.11) ----
     Examine a ClientHello for pre_shared_key + psk_key_exchange_modes. The
     server only does psk_dhe_ke (it always negotiates an (EC)DHE share),
     so psk_key_exchange_modes MUST advertise mode 1. For each offered
     identity (in order) look it up in the ticket store; the first known
     identity is the candidate. Then verify its binder MAC over the
     truncated transcript (the ClientHello up to and excluding the binder
     list, §4.2.11.2), where `chMsg` is the full ClientHello wire message
     (handshake header + body).

     Returns:
       NONE                       -- no usable PSK offered (reject: full 1-RTT)
       SOME (index, psk)          -- accept PSK at `index` with secret `psk`
     Raises Fatal IllegalParameter when a known identity's binder does not
     verify (a protocol violation, §4.2.11.2). *)
  fun selectPsk (ch : TlsHandshake.clientHello, chMsg : string)
      : (int * string) option =
    let
      val exts = #extensions ch
      fun findExt t =
        case List.find (fn {extType, ...} => extType = t) exts of
            SOME {data, ...} => SOME data
          | NONE => NONE
      val modesOk =
        case findExt TlsHandshake.extPskKeyExchangeModes of
            SOME d =>
              (case TlsExtensions.decodePskKeyExchangeModes d of
                   SOME ms => List.exists (fn m => m = TlsExtensions.pskModeDheKe) ms
                 | NONE => false)
          | NONE => false
    in
      if not modesOk then NONE
      else
        case findExt TlsHandshake.extPreSharedKey of
            NONE => NONE
          | SOME pskData =>
              (case TlsExtensions.decodeOfferedPsks pskData of
                   NONE => NONE
                 | SOME (ids, binders) =>
                     let
                       (* Find the first offered identity we recognise. *)
                       fun pick (_, [], _) = NONE
                         | pick (i, {identity, ...} :: rest, bs) =
                             (case (lookupTicket identity, bs) of
                                  (SOME psk, b :: _) => SOME (i, psk, b)
                                | (SOME _, []) => NONE  (* missing binder *)
                                | (NONE, _ :: bs') => pick (i + 1, rest, bs')
                                | (NONE, []) => NONE)
                     in
                       case pick (0, ids, binders) of
                           NONE => NONE
                         | SOME (idx, psk, clientBinder) =>
                             let
                               (* Truncate(ClientHello): drop the binder
                                  list (2-byte length prefix + entries).
                                  The binder list is the LAST thing in the
                                  pre_shared_key extension, which is the
                                  LAST extension, so it is the tail of the
                                  ClientHello wire message. *)
                               val binderStructLen =
                                 2 + TlsExtensions.binderListLength binders
                               val truncated = String.substring
                                 (chMsg, 0, String.size chMsg - binderStructLen)
                               val expected = TlsKeySchedule.pskBinder
                                 {psk = psk, transcript = truncated}
                             in
                               if expected = clientBinder then SOME (idx, psk)
                               else raise Fatal TlsAlert.IllegalParameter
                             end
                     end)
    end

  (* Emit a HelloRetryRequest (RFC 8446 §4.1.4) forcing the client to retry
     with a key_share for `group`, optionally carrying a `cookie`. Applies
     the §4.4.1 synthetic-message transcript substitution: ClientHello1 is
     replaced by message_hash || 00 00 Hash.length || Hash(ClientHello1). *)
  fun produceHelloRetryRequest (st : serverState, cfg : serverConfig,
                                {group, cookie} : {group : Word16.word,
                                                   cookie : string})
      : serverState * string =
    let
      val supVer = supportedVersionsServerExt ()
      val keyShare = {extType = TlsHandshake.extKeyShare,
                      data = TlsExtensions.encodeKeyShareHRR group}
      val cookieExt =
        if cookie = "" then []
        else [{extType = TlsHandshake.extCookie,
               data = TlsExtensions.encodeCookie cookie} : TlsHandshake.extension]
      val sessionId =
        case #clientHello st of SOME ch => #legacySessionId ch | NONE => #legacySessionId cfg
      val hrr = {
        legacyVersion = 0wx0303,
        random = TlsHandshake.helloRetryRequestRandom,
        legacySessionId = sessionId,
        cipherSuite = #cipherSuite cfg,
        legacyCompression = 0w0,
        extensions = List.concat [[keyShare, supVer], cookieExt]
      } : TlsHandshake.serverHello
      val hrrBody = TlsHandshake.encodeServerHello hrr
      val hrrMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ServerHello, body = hrrBody}
      (* Synthetic-message substitution: the transcript so far is exactly
         ClientHello1's wire message. *)
      val ch1Msg = #transcript st
      val synthetic = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.MessageHash, body = Sha256.digest ch1Msg}
      val record = TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake, fragment = hrrMsg}
      val st' = { x25519PrivateKey = #x25519PrivateKey st,
        serverRandom = #serverRandom st, cipherSuite = #cipherSuite st,
        legacySessionId = #legacySessionId st, extensions = #extensions st,
        transcript = synthetic ^ hrrMsg, dhe = #dhe st,
        clientHello = #clientHello st, serverHello = #serverHello st,
        clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
        clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
        serverHandshakeKey = #serverHandshakeKey st,
        clientHandshakeKey = #clientHandshakeKey st,
        serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
        clientHsProtect = #clientHsProtect st, clientApProtect = #clientApProtect st,
        serverApProtect = #serverApProtect st, errorAlert = #errorAlert st,
        connected = #connected st } : serverState
    in
      (st', record)
    end

  (* Process ClientHello2 after a HelloRetryRequest: append it to the
     (already synthetic-substituted) transcript and adopt it as the active
     ClientHello. `ch2Body` is the ClientHello body (no handshake header). *)
  fun receiveSecondClientHello (st : serverState, ch2Body : string)
      : serverState =
    case TlsHandshake.decodeClientHello ch2Body of
        NONE => raise Tls "malformed ClientHello2"
      | SOME ch2 =>
          let
            val ch2Msg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.ClientHello, body = ch2Body}
          in
            { x25519PrivateKey = #x25519PrivateKey st,
              serverRandom = #serverRandom st, cipherSuite = #cipherSuite st,
              legacySessionId = #legacySessionId st, extensions = #extensions st,
              transcript = #transcript st ^ ch2Msg, dhe = #dhe st,
              clientHello = SOME ch2, serverHello = #serverHello st,
              clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
              clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
              serverHandshakeKey = #serverHandshakeKey st,
              clientHandshakeKey = #clientHandshakeKey st,
              serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
              clientHsProtect = #clientHsProtect st, clientApProtect = #clientApProtect st,
              serverApProtect = #serverApProtect st, errorAlert = #errorAlert st,
              connected = #connected st } : serverState
          end

  fun produceServerHello (st : serverState, cfg : serverConfig) : serverState * string =
    let
      (* Negotiate the key-share group from the client's offered shares. *)
      val ch = case #clientHello st of
                   NONE => raise Tls "no ClientHello"
                 | SOME c => c
      (* The full ClientHello wire message, for the PSK binder transcript
         truncation (§4.2.11.2). For a non-HRR handshake the server
         transcript IS exactly this message. *)
      val chMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ClientHello, body = TlsHandshake.encodeClientHello ch}
      (* PSK resumption decision (verifies the binder; raises Fatal
         IllegalParameter on a known-identity binder mismatch). *)
      val pskSel = selectPsk (ch, chMsg)
      val shares = clientKeyShares ch
      val group =
        case TlsExtensions.negotiateGroup
               {clientShares = shares, serverGroups = serverGroups cfg} of
            SOME g => g
          | NONE => raise Tls "no common key_share group"
      val peerPub =
        case List.find (fn {group = g, ...} => g = group) shares of
            SOME {keyExchange, ...} => keyExchange
          | NONE => raise Tls "negotiated group has no client share"
      val (serverPub, dhe) = serverShareAndDhe (cfg, group, peerPub)
      val keyShare = serverKeyShareExt (group, serverPub)
      val supVer = supportedVersionsServerExt ()
      (* On PSK accept, echo selected_identity (§4.2.11). The pre_shared_key
         extension MUST be last in the ServerHello. *)
      val pskExtSH =
        case pskSel of
            SOME (idx, _) =>
              [{extType = TlsHandshake.extPreSharedKey,
                data = TlsExtensions.encodeSelectedIdentity (Word16.fromInt idx)}
               : TlsHandshake.extension]
          | NONE => []
      val exts = List.concat [#extensions cfg, [keyShare, supVer], pskExtSH]
      val sh = {
        legacyVersion = 0wx0303,
        random = #serverRandom cfg,
        legacySessionId = #legacySessionId cfg,
        cipherSuite = #cipherSuite cfg,
        legacyCompression = 0w0,
        extensions = exts
      } : TlsHandshake.serverHello
      val shBody = TlsHandshake.encodeServerHello sh
      val shMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ServerHello, body = shBody}
      val transcript = #transcript st ^ shMsg
      (* PSK resumption seeds the Early-Secret with the resumption PSK
         (psk_dhe_ke); a full handshake uses a zero PSK. *)
      val sched =
        case pskSel of
            SOME (_, psk) =>
              TlsKeySchedule.schedulePsk {
                psk = psk, dhe = dhe,
                handshakeTranscript = transcript, applicationTranscript = ""}
          | NONE =>
              TlsKeySchedule.schedule {
                dhe = dhe,
                handshakeTranscript = transcript, applicationTranscript = ""}
      val cs = #cipherSuite cfg
      val (keyLen, ivLen) =
        if cs = TlsHandshake.suiteTlsAes128GcmSha256 orelse
           cs = TlsHandshake.suiteTlsChaCha20Poly1305 then (16, 12)
        else if cs = TlsHandshake.suiteTlsAes256GcmSha384 then (32, 12)
        else (16, 12)
      val cHsSec = Secret.fromString (#clientHandshakeSecret sched)
      val sHsSec = Secret.fromString (#serverHandshakeSecret sched)
      val sHsKey = Secret.fromString (TlsKeySchedule.trafficKey
        {secret = #serverHandshakeSecret sched, keyLength = keyLen})
      val sHsIv = Secret.fromString (TlsKeySchedule.trafficIv
        {secret = #serverHandshakeSecret sched, ivLength = ivLen})
      val cHsKey = Secret.fromString (TlsKeySchedule.trafficKey
        {secret = #clientHandshakeSecret sched, keyLength = keyLen})
      val cHsIv = Secret.fromString (TlsKeySchedule.trafficIv
        {secret = #clientHandshakeSecret sched, ivLength = ivLen})
      val record = TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake, fragment = shMsg}
      val st' = {
        x25519PrivateKey = Secret.fromString (#x25519PrivateKey cfg),
        serverRandom = #serverRandom cfg,
        cipherSuite = SOME cs,
        legacySessionId = #legacySessionId cfg,
        extensions = #extensions cfg,
        transcript = transcript,
        dhe = Secret.fromString dhe,
        clientHello = #clientHello st,
        serverHello = SOME sh,
        clientHsSecret = SOME cHsSec,
        serverHsSecret = SOME sHsSec,
        clientApSecret = NONE,
        serverApSecret = NONE,
        serverHandshakeKey = SOME (sHsKey, sHsIv),
        clientHandshakeKey = SOME (cHsKey, cHsIv),
        serverAppKey = NONE,
        clientAppKey = NONE,
        clientHsProtect = SOME (mkProtect (cs, (cHsKey, cHsIv))),
        clientApProtect = NONE,
        serverApProtect = NONE,
        errorAlert = NONE,
        connected = false
      } : serverState
    in
      (st', record)
    end
    handle Fatal desc => (setError (st, desc), alertRecord desc)

  (* Encode the inner EncryptedExtensions, Certificate, CertificateVerify and
     server Finished, then AEAD-protect each as its own record under the
     server handshake-traffic key (write seq 0,1,2,3).  Derives the
     application-traffic keys from the transcript through the server
     Finished and stores them for the post-handshake phase. *)
  fun produceServerFlight (st : serverState, cfg : serverConfig)
      : serverState * string =
    let
      val cs = Option.valOf (#cipherSuite st)
      val (keyLen, ivLen) = suiteKeyIvLen cs
      val serverHsSecret = Secret.toBytes (Option.valOf (#serverHsSecret st))
      val sHsKiv = Option.valOf (#serverHandshakeKey st)
      (* PSK resumption: a handshake authenticated by the PSK omits the
         server Certificate / CertificateVerify (RFC 8446 §2.2, §4.4.2) and
         seeds all secrets with the resumption PSK. Detect acceptance from
         the stored ServerHello (carries pre_shared_key) and recover the PSK
         by re-running the (idempotent, binder-verified) selection over the
         stored ClientHello. *)
      val resumePsk =
        case #serverHello st of
            SOME sh =>
              if List.exists
                   (fn {extType, ...} => extType = TlsHandshake.extPreSharedKey)
                   (#extensions sh)
              then
                (case #clientHello st of
                     SOME ch =>
                       let val chMsg = TlsHandshake.encodeMessage
                             {msgType = TlsHandshake.ClientHello,
                              body = TlsHandshake.encodeClientHello ch}
                       in Option.map #2 (selectPsk (ch, chMsg)) end
                   | NONE => NONE)
              else NONE
          | NONE => NONE
      (* EncryptedExtensions: empty extension block for this minimal server. *)
      val eeBody = TlsHandshake.encodeEncryptedExtensions []
      val eeMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.EncryptedExtensions, body = eeBody}
      (* Certificate: the configured chain, each entry with no extensions. *)
      val certEntries = List.map
        (fn der => {certData = der, extensions = []}) (#certChain cfg)
      val certBody = TlsHandshake.encodeCertificate
        {certificateRequestContext = "", certificateList = certEntries}
      val certMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.Certificate, body = certBody}
      (* CertificateVerify (RFC 8446 §4.4.3).  When an RSA private key is
         configured, RSA-PSS-sign the transcript hash THROUGH the Certificate
         message and emit a real signature.  When no key is configured
         (`rsaPrivateKeyDer = ""`), fall back to the legacy empty-signature CV
         (handshake authenticity then rides only on the Finished MAC); this
         keeps PKI-less handshake tests working. *)
      val tBeforeCv = #transcript st ^ eeMsg ^ certMsg
      val cvSigBytes =
        if #rsaPrivateKeyDer cfg = "" then ""
        else
          let val priv = Rsa.decodePkcs8Der (#rsaPrivateKeyDer cfg) in
            TlsKeySchedule.signServerCertVerify
              {priv = priv, sigAlg = #sigAlg cfg, transcript = tBeforeCv}
          end
      val cvBody = TlsHandshake.encodeCertificateVerify
        {sigAlg = #sigAlg cfg, sigBytes = cvSigBytes}
      val cvMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.CertificateVerify, body = cvBody}
      (* On PSK resumption, the flight is EE..ServerFinished (no Cert/CV). *)
      val isResume = Option.isSome resumePsk
      val tBeforeFin =
        if isResume then #transcript st ^ eeMsg else tBeforeCv ^ cvMsg
      val sfKey = TlsKeySchedule.finishedKey {secret = serverHsSecret}
      val sfVerify = TlsKeySchedule.finishedVerifyData
        {finishedKey = sfKey, transcript = tBeforeFin}
      val sfBody = TlsHandshake.encodeFinished {verifyData = sfVerify}
      val sfMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.Finished, body = sfBody}
      val transcript' = tBeforeFin ^ sfMsg
      (* Application-traffic keys from the transcript through server Finished;
         seed with the resumption PSK when resuming. *)
      val sched =
        case resumePsk of
            SOME psk => TlsKeySchedule.schedulePsk {
              psk = psk, dhe = Secret.toBytes (#dhe st),
              handshakeTranscript = #transcript st,
              applicationTranscript = transcript'}
          | NONE => TlsKeySchedule.schedule {
              dhe = Secret.toBytes (#dhe st),
              handshakeTranscript = #transcript st,
              applicationTranscript = transcript'}
      val sApSecB = #serverAppSecret sched
      val cApSecB = #clientAppSecret sched
      val sApSec = Secret.fromString sApSecB
      val cApSec = Secret.fromString cApSecB
      val sApKey = Secret.fromString (TlsKeySchedule.trafficKey {secret = sApSecB, keyLength = keyLen})
      val sApIv  = Secret.fromString (TlsKeySchedule.trafficIv  {secret = sApSecB, ivLength = ivLen})
      val cApKey = Secret.fromString (TlsKeySchedule.trafficKey {secret = cApSecB, keyLength = keyLen})
      val cApIv  = Secret.fromString (TlsKeySchedule.trafficIv  {secret = cApSecB, ivLength = ivLen})
      (* Protect each handshake message as its own record under the server HS
         key, threading the write seq. *)
      fun emit (prot, msg) =
        let val (body, prot') = TlsRecordProtect.protect
              {state = prot, innerType = TlsRecord.Handshake,
               plaintext = msg, pad = 0}
        in (prot', TlsRecord.encodeCiphertext
              {contentType = TlsRecord.ApplicationData, encryptedRecord = body})
        end
      val p0 = mkProtect (cs, sHsKiv)
      val (p1, r1) = emit (p0, eeMsg)
      val flight =
        if isResume then
          let val (_, r4) = emit (p1, sfMsg) in r1 ^ r4 end
        else
          let
            val (p2, r2) = emit (p1, certMsg)
            val (p3, r3) = emit (p2, cvMsg)
            val (_,  r4) = emit (p3, sfMsg)
          in r1 ^ r2 ^ r3 ^ r4 end
      val st' = {
        x25519PrivateKey = #x25519PrivateKey st,
        serverRandom = #serverRandom st,
        cipherSuite = #cipherSuite st,
        legacySessionId = #legacySessionId st,
        extensions = #extensions st,
        transcript = transcript',
        dhe = #dhe st,
        clientHello = #clientHello st,
        serverHello = #serverHello st,
        clientHsSecret = #clientHsSecret st,
        serverHsSecret = #serverHsSecret st,
        clientApSecret = SOME cApSec,
        serverApSecret = SOME sApSec,
        serverHandshakeKey = #serverHandshakeKey st,
        clientHandshakeKey = #clientHandshakeKey st,
        serverAppKey = SOME (sApKey, sApIv),
        clientAppKey = SOME (cApKey, cApIv),
        clientHsProtect = #clientHsProtect st,
        clientApProtect = SOME (mkProtect (cs, (cApKey, cApIv))),
        serverApProtect = SOME (mkProtect (cs, (sApKey, sApIv))),
        errorAlert = NONE,
        connected = false
      } : serverState
    in
      (st', flight)
    end

  (* Issue a NewSessionTicket, AEAD-protected under the server
     application-traffic key (post-handshake).  `nstBody` is the already
     encoded NewSessionTicket handshake-message body. *)
  fun produceNewSessionTicket (st : serverState, cfg : serverConfig,
                               nstBody : string) : serverState * string =
    case (#cipherSuite st, #serverApProtect st) of
        (SOME cs, SOME prot) =>
          let
            val nstMsg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.NewSessionTicket, body = nstBody}
            val (body, prot') = TlsRecordProtect.protect
              {state = prot, innerType = TlsRecord.Handshake,
               plaintext = nstMsg, pad = 0}
            val record = TlsRecord.encodeCiphertext
              {contentType = TlsRecord.ApplicationData, encryptedRecord = body}
            (* Register the resumption PSK in the ticket store, keyed by the
               ticket's opaque identity bytes (RFC 8446 §4.6.1 / §7.1).
                 resumption_master_secret = Derive-Secret(Master, "res master",
                     ClientHello..client Finished)
                 PSK = HKDF-Expand-Label(res_master, "resumption", ticketNonce)
               The master secret depends only on (EC)DHE (zero PSK on the
               issuing full handshake); the resumption master secret binds the
               complete handshake transcript held in #transcript at this point
               (through the client Finished). *)
            val () =
              case TlsHandshake.decodeNewSessionTicket nstBody of
                  SOME {ticket, ticketNonce, ...} =>
                    if ticket = "" then ()
                    else
                      let
                        val ms = #masterSecret (TlsKeySchedule.schedule
                          {dhe = Secret.toBytes (#dhe st), handshakeTranscript = "",
                           applicationTranscript = ""})
                        val rms = TlsKeySchedule.resumptionMasterSecret
                          {masterSecret = ms, transcript = #transcript st}
                        val psk = TlsKeySchedule.resumptionPsk
                          {resumptionMasterSecret = rms, ticketNonce = ticketNonce}
                      in
                        storeTicket (ticket, psk)
                      end
                | NONE => ()
            val st' = {
              x25519PrivateKey = #x25519PrivateKey st,
              serverRandom = #serverRandom st,
              cipherSuite = #cipherSuite st,
              legacySessionId = #legacySessionId st,
              extensions = #extensions st,
              transcript = #transcript st,
              dhe = #dhe st,
              clientHello = #clientHello st,
              serverHello = #serverHello st,
              clientHsSecret = #clientHsSecret st,
              serverHsSecret = #serverHsSecret st,
              clientApSecret = #clientApSecret st,
              serverApSecret = #serverApSecret st,
              serverHandshakeKey = #serverHandshakeKey st,
              clientHandshakeKey = #clientHandshakeKey st,
              serverAppKey = #serverAppKey st,
              clientAppKey = #clientAppKey st,
              clientHsProtect = #clientHsProtect st,
              clientApProtect = #clientApProtect st,
              serverApProtect = SOME prot',
              errorAlert = #errorAlert st,
              connected = #connected st
            } : serverState
          in
            (st', record)
          end
      | _ => raise Tls "produceNewSessionTicket: no server app key"

  (* Update just the client-app read protect-state. *)
  fun withClientApProtect (st : serverState, prot') : serverState =
    { x25519PrivateKey = #x25519PrivateKey st, serverRandom = #serverRandom st,
      cipherSuite = #cipherSuite st, legacySessionId = #legacySessionId st,
      extensions = #extensions st, transcript = #transcript st, dhe = #dhe st,
      clientHello = #clientHello st, serverHello = #serverHello st,
      clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
      clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
      serverHandshakeKey = #serverHandshakeKey st,
      clientHandshakeKey = #clientHandshakeKey st,
      serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
      clientHsProtect = #clientHsProtect st, clientApProtect = SOME prot',
      serverApProtect = #serverApProtect st, errorAlert = #errorAlert st,
      connected = #connected st }

  (* Rekey the client-app read side after an incoming KeyUpdate (§7.2). *)
  fun rekeyClientRead (st : serverState) : serverState =
    let
      val cs = Option.valOf (#cipherSuite st)
      val (kl, il) = suiteKeyIvLen cs
      val next = nextAppSecret (Secret.toBytes (Option.valOf (#clientApSecret st)))
      val nextS = Secret.fromString next
      val k = Secret.fromString (TlsKeySchedule.trafficKey {secret = next, keyLength = kl})
      val iv = Secret.fromString (TlsKeySchedule.trafficIv {secret = next, ivLength = il})
    in
      { x25519PrivateKey = #x25519PrivateKey st, serverRandom = #serverRandom st,
        cipherSuite = #cipherSuite st, legacySessionId = #legacySessionId st,
        extensions = #extensions st, transcript = #transcript st, dhe = #dhe st,
        clientHello = #clientHello st, serverHello = #serverHello st,
        clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
        clientApSecret = SOME nextS, serverApSecret = #serverApSecret st,
        serverHandshakeKey = #serverHandshakeKey st,
        clientHandshakeKey = #clientHandshakeKey st,
        serverAppKey = #serverAppKey st, clientAppKey = SOME (k, iv),
        clientHsProtect = #clientHsProtect st,
        clientApProtect = SOME (mkProtect (cs, (k, iv))),
        serverApProtect = #serverApProtect st, errorAlert = #errorAlert st,
        connected = #connected st }
    end

  (* Mark the server connected (after receiving the client Finished). *)
  fun markConnected (st : serverState) : serverState =
    { x25519PrivateKey = #x25519PrivateKey st, serverRandom = #serverRandom st,
      cipherSuite = #cipherSuite st, legacySessionId = #legacySessionId st,
      extensions = #extensions st, transcript = #transcript st, dhe = #dhe st,
      clientHello = #clientHello st, serverHello = #serverHello st,
      clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
      clientApSecret = #clientApSecret st, serverApSecret = #serverApSecret st,
      serverHandshakeKey = #serverHandshakeKey st,
      clientHandshakeKey = #clientHandshakeKey st,
      serverAppKey = #serverAppKey st, clientAppKey = #clientAppKey st,
      clientHsProtect = #clientHsProtect st, clientApProtect = #clientApProtect st,
      serverApProtect = #serverApProtect st, errorAlert = #errorAlert st,
      connected = true }

  (* True iff the client's ClientHello offered the early_data extension
     (RFC 8446 §4.2.10). This server never accepts a PSK, so any offered
     early_data is rejected: the EncryptedExtensions omit early_data and the
     undecryptable 0-RTT records are skipped (§2.3 / §4.2.10). *)
  fun clientOfferedEarlyData (st : serverState) =
    case #clientHello st of
        SOME ch =>
          List.exists (fn {extType, ...} => extType = TlsHandshake.extEarlyData)
                      (#extensions ch)
      | NONE => false

  (* DoS bound on how many bytes of rejected early data we skip (§4.2.10:
     a server ignores early data up to max_early_data_size). One record. *)
  val maxEarlyDataReject = 16384

  (* Feed received ciphertext records to the server.  During the handshake
     this is the client Finished (under the client HS key); once connected it
     is application data / KeyUpdate (under the client app key).

     When the client offered (rejected) 0-RTT early_data, the flight before
     the client Finished may be preceded by application_data records that
     the server cannot decrypt (they are under the client_early_traffic
     key). Those are skipped without advancing the handshake read sequence;
     an EndOfEarlyData handshake message (§4.5) is likewise skipped. *)
  fun step (st : serverState, input : string) : serverState * string list =
    if Option.isSome (#errorAlert st) then (st, [])
    else if input = "" then (st, [])
    else
      (if not (#connected st) then
         (* Loop, skipping rejected early data, until the client Finished. *)
         let
           fun hsLoop (remaining, prot, skipped) =
             if remaining = "" then (st, [])  (* no Finished yet; keep waiting *)
             else
               case TlsRecord.decodeCiphertext remaining of
                   NONE => raise Fatal TlsAlert.DecodeError
                 | SOME (crec, rest) =>
                     if #contentType crec = TlsRecord.ChangeCipherSpec then
                       hsLoop (rest, prot, skipped)
                     else if String.size (#encryptedRecord crec) > maxCiphertextLen then
                       raise Fatal TlsAlert.RecordOverflow
                     else
                       case TlsRecordProtect.unprotect
                              {state = prot, record = #encryptedRecord crec} of
                           NONE =>
                             (* Undecryptable under the HS key: a rejected
                                0-RTT record (skip) iff early_data was
                                offered; otherwise a genuine MAC failure. *)
                             if clientOfferedEarlyData st then
                               let val skipped' =
                                     skipped + String.size (#encryptedRecord crec)
                               in
                                 if skipped' > maxEarlyDataReject
                                 then raise Fatal TlsAlert.UnexpectedMessage
                                 else hsLoop (rest, prot, skipped')
                               end
                             else raise Fatal TlsAlert.BadRecordMac
                         | SOME (TlsRecord.Handshake, pt, prot') =>
                             (case TlsHandshake.decodeMessage pt of
                                  SOME ({msgType = TlsHandshake.EndOfEarlyData, ...}, _) =>
                                    hsLoop (rest, prot', skipped)
                                | SOME ({msgType = TlsHandshake.Finished, body}, _) =>
                                    let
                                      val cfKey = TlsKeySchedule.finishedKey
                                        {secret = Secret.toBytes (Option.valOf (#clientHsSecret st))}
                                      val expected = TlsKeySchedule.finishedVerifyData
                                        {finishedKey = cfKey, transcript = #transcript st}
                                    in
                                      if expected = body then (markConnected st, [])
                                      else raise Fatal TlsAlert.DecryptError
                                    end
                                | _ => raise Fatal TlsAlert.UnexpectedMessage)
                         | SOME (_, _, _) => raise Fatal TlsAlert.UnexpectedMessage
         in
           hsLoop (input, Option.valOf (#clientHsProtect st), 0)
         end
       else
         (* Connected: decrypt application data / KeyUpdate under client app key. *)
         (case TlsRecord.decodeCiphertext input of
              NONE => raise Fatal TlsAlert.DecodeError
            | SOME (crec, _) =>
                if #contentType crec = TlsRecord.ChangeCipherSpec then (st, [])
                else if String.size (#encryptedRecord crec) > maxCiphertextLen then
                  raise Fatal TlsAlert.RecordOverflow
                else
                  let val prot = Option.valOf (#clientApProtect st) in
                    case TlsRecordProtect.unprotect
                           {state = prot, record = #encryptedRecord crec} of
                        NONE => raise Fatal TlsAlert.BadRecordMac
                      | SOME (innerCt, pt, prot') =>
                          let val st1 = withClientApProtect (st, prot') in
                            case innerCt of
                                TlsRecord.Handshake =>
                                  (case TlsHandshake.decodeMessage pt of
                                       SOME ({msgType = TlsHandshake.KeyUpdate, ...}, _) =>
                                         (rekeyClientRead st1, [])
                                     | _ => (st1, []))
                              | _ => (st1, [])
                          end
                  end))
      handle Fatal desc => (setError (st, desc), [alertRecord desc])
           (* Backstop: never let malformed peer input crash `step`. *)
           | _ => (setError (st, TlsAlert.DecodeError),
                   [alertRecord TlsAlert.DecodeError])

  fun error (st : serverState) : Word8.word option = #errorAlert st

  fun negotiatedCipherSuite (st : serverState) = #cipherSuite st
  local
    fun kivBytes NONE = NONE
      | kivBytes (SOME (k, iv)) = SOME (Secret.toBytes k, Secret.toBytes iv)
  in
    fun serverHandshakeKey (st : serverState) = kivBytes (#serverHandshakeKey st)
    fun clientHandshakeKey (st : serverState) = kivBytes (#clientHandshakeKey st)
    fun serverAppKey (st : serverState) = kivBytes (#serverAppKey st)
    fun clientAppKey (st : serverState) = kivBytes (#clientAppKey st)
  end
  fun transcript (st : serverState) = #transcript st
  fun isConnected (st : serverState) = #connected st

  (* ---- Track 1b: secure zeroing of server key material ---- *)
  (* In-place wipe of every reference-shared secret buffer the state holds,
     plus the old TlsRecordProtect key/iv buffers and the PSK ticket store,
     then return the SAME state. Observable through every alias (see the
     client `zeroize` for the rationale). *)
  local
    fun wOpt NONE = () | wOpt (SOME s) = Secret.wipe s
    fun wKey NONE = () | wKey (SOME (k, iv)) = (Secret.wipe k; Secret.wipe iv)
    fun wProt NONE = () | wProt (SOME st) =
      (Secret.wipe (TlsRecordProtect.keySecret st);
       Secret.wipe (TlsRecordProtect.ivSecret st))
  in
    fun zeroize (st : serverState) : serverState =
      ( Secret.wipe (#x25519PrivateKey st)
      ; Secret.wipe (#dhe st)
      ; wOpt (#clientHsSecret st)
      ; wOpt (#serverHsSecret st)
      ; wOpt (#clientApSecret st)
      ; wOpt (#serverApSecret st)
      ; wKey (#serverHandshakeKey st)
      ; wKey (#clientHandshakeKey st)
      ; wKey (#serverAppKey st)
      ; wKey (#clientAppKey st)
      ; wProt (#clientHsProtect st)
      ; wProt (#clientApProtect st)
      ; wProt (#serverApProtect st)
      (* Wipe the process-wide PSK resumption store on teardown. *)
      ; clearTicketStore ()
      ; st )
  end

  fun zeroizeConfig (cfg : serverConfig) : serverConfig =
    { x25519PrivateKey = SecureZero.zeroString (#x25519PrivateKey cfg),
      p256PrivateKey =
        (case #p256PrivateKey cfg of
             NONE => NONE
           | SOME s => SOME (SecureZero.zeroString s)),
      serverRandom = #serverRandom cfg,
      cipherSuite = #cipherSuite cfg,
      legacySessionId = #legacySessionId cfg,
      extensions = #extensions cfg,
      certChain = #certChain cfg,
      rsaPrivateKeyDer = SecureZero.zeroString (#rsaPrivateKeyDer cfg),
      sigAlg = #sigAlg cfg,
      now = #now cfg,
      sigAlgs = #sigAlgs cfg }

  fun secretsForTest (st : serverState) : string list =
    let
      fun ofKey NONE = [] | ofKey (SOME (k, iv)) = [Secret.toBytes k, Secret.toBytes iv]
      fun ofOpt NONE = [] | ofOpt (SOME s) = [Secret.toBytes s]
    in
      [Secret.toBytes (#x25519PrivateKey st), Secret.toBytes (#dhe st)]
      @ ofOpt (#clientHsSecret st) @ ofOpt (#serverHsSecret st)
      @ ofOpt (#clientApSecret st) @ ofOpt (#serverApSecret st)
      @ ofKey (#serverHandshakeKey st) @ ofKey (#clientHandshakeKey st)
      @ ofKey (#serverAppKey st) @ ofKey (#clientAppKey st)
    end

  (* Test-only hooks into the PSK ticket store, so the zeroize suite can seed
     a resumption PSK and observe it wiped at teardown. *)
  fun storeTicketForTest (id, psk) = storeTicket (id, psk)
  fun ticketStoreSecretsForTest () =
    List.map (fn (_, psk) => Secret.toBytes psk) (!ticketStore)
end

structure Tls :> TLS =
struct
  structure TlsRecord      = TlsRecord
  structure TlsAlert       = TlsAlert
  structure TlsHandshake   = TlsHandshake
  structure TlsKeySchedule = TlsKeySchedule
  structure TlsClient      = TlsClient
  structure TlsServer      = TlsServer
end
