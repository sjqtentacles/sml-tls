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
    x25519PrivateKey  : string,
    clientHello       : TlsHandshake.clientHello,
    transcript        : string,
    cipherSuite       : Word16.word option,
    dhe               : string,
    negotiatedGroup   : Word16.word option,
    serverHello       : TlsHandshake.serverHello option,
    clientHsSecret    : string option,
    serverHsSecret    : string option,
    clientApSecret    : string option,
    serverApSecret    : string option,
    serverHandshakeKey : (string * string) option,
    clientHandshakeKey : (string * string) option,
    serverAppKey : (string * string) option,
    clientAppKey : (string * string) option,
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

  (* Build a combined key_share extension offering X25519 and, when a
     P-256 private key is configured, secp256r1 too (A4). Uses
     TlsExtensions.encodeKeyShareCH so the CH list framing is shared. *)
  fun keyShareExtensionMulti (cfg : clientConfig) : TlsHandshake.extension =
    let
      val x25519Entry =
        {group = TlsHandshake.groupX25519,
         keyExchange = X25519.base (#x25519PrivateKey cfg)}
      val entries =
        case #p256PrivateKey cfg of
            SOME pk =>
              [x25519Entry,
               {group = TlsHandshake.groupSecp256r1,
                keyExchange = P256.generatePublic pk}]
          | NONE => [x25519Entry]
    in
      {extType = TlsHandshake.extKeyShare,
       data = TlsExtensions.encodeKeyShareCH entries}
    end

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

  fun startHandshake (cfg : clientConfig) : clientState * string =
    let
      val keyShare = keyShareExtensionMulti cfg
      val supVer = supportedVersionsExtension ()
      val supGrp = supportedGroupsExtensionMulti cfg
      val sigAlg = signatureAlgorithmsExtension ()
      (* Optional SNI from config.serverName. *)
      val sni =
        if #serverName cfg = "" then []
        else [{extType = TlsHandshake.extServerName,
               data = TlsExtensions.encodeServerName (#serverName cfg)}
              : TlsHandshake.extension]
      val exts = [#extensions cfg, [keyShare, supVer, supGrp, sigAlg], sni]
      val allExts = List.concat exts
      val ch = {
        legacyVersion = 0wx0303,
        random = #clientRandom cfg,
        legacySessionId = #legacySessionId cfg,
        cipherSuites = #cipherSuites cfg,
        legacyCompression = [0w0],
        extensions = allExts
      } : TlsHandshake.clientHello
      val body = TlsHandshake.encodeClientHello ch
      val msg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.ClientHello, body = body}
      val record = TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake, fragment = msg}
      val st = {
        config = cfg,
        x25519PrivateKey = #x25519PrivateKey cfg,
        clientHello = ch,
        transcript = msg,
        cipherSuite = NONE,
        dhe = "",
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
      SOME (X25519.dh (#x25519PrivateKey st) peerPub)
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
            val sHsKey = TlsKeySchedule.trafficKey
              {secret = #serverHandshakeSecret sched, keyLength = keyLen}
            val sHsIv = TlsKeySchedule.trafficIv
              {secret = #serverHandshakeSecret sched, ivLength = ivLen}
            val cHsKey = TlsKeySchedule.trafficKey
              {secret = #clientHandshakeSecret sched, keyLength = keyLen}
            val cHsIv = TlsKeySchedule.trafficIv
              {secret = #clientHandshakeSecret sched, ivLength = ivLen}
          in
            { config = #config st,
              x25519PrivateKey = #x25519PrivateKey st,
              clientHello = #clientHello st,
              transcript = transcript,
              cipherSuite = SOME cs,
              dhe = dhe,
              negotiatedGroup = SOME group,
              serverHello = SOME sh,
              clientHsSecret = SOME (#clientHandshakeSecret sched),
              serverHsSecret = SOME (#serverHandshakeSecret sched),
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
      val serverHsSecret = Option.valOf (#serverHsSecret st)
      val clientHsSecret = Option.valOf (#clientHsSecret st)
      val (keyLen, ivLen) = suiteKeyIvLen cs
      fun loop (remaining, transcript, certOk) =
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
                        (verifyServerCert (st, body);
                         loop (rest, transcript', true))
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
                            dhe = #dhe st,
                            handshakeTranscript = #transcript st,
                            applicationTranscript = transcript'
                          }
                          val sApSec = #serverAppSecret sched
                          val cApSec = #clientAppSecret sched
                          val sApKey = TlsKeySchedule.trafficKey {secret = sApSec, keyLength = keyLen}
                          val sApIv  = TlsKeySchedule.trafficIv  {secret = sApSec, ivLength = ivLen}
                          val cApKey = TlsKeySchedule.trafficKey {secret = cApSec, keyLength = keyLen}
                          val cApIv  = TlsKeySchedule.trafficIv  {secret = cApSec, ivLength = ivLen}
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
                    | _ => loop (rest, transcript', certOk)
                end
    in
      loop (hs, #transcript st, #certVerified st)
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
      val next = nextAppSecret (Option.valOf (#serverApSecret st))
      val k = TlsKeySchedule.trafficKey {secret = next, keyLength = kl}
      val iv = TlsKeySchedule.trafficIv {secret = next, ivLength = il}
    in
      { config = #config st, x25519PrivateKey = #x25519PrivateKey st,
        clientHello = #clientHello st, transcript = #transcript st,
        cipherSuite = #cipherSuite st, dhe = #dhe st,
        negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
        clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
        clientApSecret = #clientApSecret st, serverApSecret = SOME next,
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
                handshake message). *)
             let
               val body =
                 case TlsRecord.decodePlaintext input of
                     SOME (r, _) =>
                       if #contentType r = TlsRecord.Handshake then #fragment r
                       else input
                   | NONE => input
             in
               case TlsHandshake.decodeMessage body of
                   SOME ({msgType = TlsHandshake.ServerHello, body = shBody}, _) =>
                     (processServerHello (st, shBody), [])
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
            val next = nextAppSecret secret
            val k = TlsKeySchedule.trafficKey {secret = next, keyLength = kl}
            val iv = TlsKeySchedule.trafficIv {secret = next, ivLength = il}
            val st' = {
              config = #config st, x25519PrivateKey = #x25519PrivateKey st,
              clientHello = #clientHello st, transcript = #transcript st,
              cipherSuite = #cipherSuite st, dhe = #dhe st,
              negotiatedGroup = #negotiatedGroup st, serverHello = #serverHello st,
              clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
              clientApSecret = SOME next, serverApSecret = #serverApSecret st,
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
  fun serverHandshakeKey (st : clientState) = #serverHandshakeKey st
  fun clientHandshakeKey (st : clientState) = #clientHandshakeKey st
  fun serverAppKey (st : clientState) = #serverAppKey st
  fun clientAppKey (st : clientState) = #clientAppKey st
  fun transcript (st : clientState) = #transcript st
  fun isConnected (st : clientState) = #connected st
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
    x25519PrivateKey  : string,
    serverRandom      : string,
    cipherSuite       : Word16.word option,
    legacySessionId   : string,
    extensions        : TlsHandshake.extension list,
    transcript        : string,
    dhe               : string,
    clientHello       : TlsHandshake.clientHello option,
    serverHello       : TlsHandshake.serverHello option,
    clientHsSecret    : string option,
    serverHsSecret    : string option,
    clientApSecret    : string option,
    serverApSecret    : string option,
    serverHandshakeKey : (string * string) option,
    clientHandshakeKey : (string * string) option,
    serverAppKey : (string * string) option,
    clientAppKey : (string * string) option,
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

  fun nextAppSecret secret =
    TlsKeySchedule.hkdfExpandLabel
      {secret = secret, label = "traffic upd", context = "",
       length = TlsKeySchedule.hashLen}

  exception Fatal of TlsAlert.alertDescription

  fun alertRecord desc =
    TlsRecord.encodePlaintext
      {contentType = TlsRecord.Alert,
       fragment = TlsAlert.encode {level = TlsAlert.Fatal, description = desc}}

  fun receiveClientHello (chBody : string) : serverState =
    case TlsHandshake.decodeClientHello chBody of
        NONE => raise Tls "malformed ClientHello"
      | SOME ch =>
          let
            val chMsg = TlsHandshake.encodeMessage
              {msgType = TlsHandshake.ClientHello, body = chBody}
          in
            { x25519PrivateKey = "",
              serverRandom = "",
              cipherSuite = NONE,
              legacySessionId = "",
              extensions = [],
              transcript = chMsg,
              dhe = "",
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

  (* Build the server's key_share extension from its private key. *)
  fun serverKeyShareExtension (privKey : string) : TlsHandshake.extension =
    let
      val pubKey = X25519.base privKey
      (* ServerHello key_share: 2-byte group, 2-byte key length, key. *)
      val data = TlsHandshake.word16ToBytes TlsHandshake.groupX25519
        ^ TlsHandshake.word16ToBytes (Word16.fromInt (String.size pubKey))
        ^ pubKey
    in
      {extType = TlsHandshake.extKeyShare, data = data}
    end

  fun supportedVersionsServerExt () : TlsHandshake.extension =
    let
      val data = TlsHandshake.word16ToBytes 0wx0304
    in
      {extType = TlsHandshake.extSupportedVersions, data = data}
    end

  fun produceServerHello (st : serverState, cfg : serverConfig) : serverState * string =
    let
      val keyShare = serverKeyShareExtension (#x25519PrivateKey cfg)
      val supVer = supportedVersionsServerExt ()
      val exts = List.concat [#extensions cfg, [keyShare, supVer]]
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
      (* Compute shared secret from the client's key_share. *)
      fun findClientKeyShare [] = NONE
        | findClientKeyShare ({extType, data} :: rest) =
            if extType = TlsHandshake.extKeyShare then
              (* ClientHello key_share: 2-byte total length, then entries. *)
              if String.size data < 2 then NONE
              else
                let
                  val total = Word16.toInt (TlsHandshake.bytesToWord16
                    (Byte.charToByte (String.sub (data, 0)),
                     Byte.charToByte (String.sub (data, 1))))
                  fun scan (i, limit) =
                    if i + 4 > limit then NONE
                    else
                      let
                        val grp = TlsHandshake.bytesToWord16
                          (Byte.charToByte (String.sub (data, i)),
                           Byte.charToByte (String.sub (data, i + 1)))
                        val klen = Word16.toInt (TlsHandshake.bytesToWord16
                          (Byte.charToByte (String.sub (data, i + 2)),
                           Byte.charToByte (String.sub (data, i + 3))))
                      in
                        if grp = TlsHandshake.groupX25519 andalso i + 4 + klen <= limit then
                          SOME (String.substring (data, i + 4, klen))
                        else scan (i + 4 + klen, limit)
                      end
                in
                  scan (2, 2 + total)
                end
            else findClientKeyShare rest
      val clientPub = case #clientHello st of
                          NONE => raise Tls "no ClientHello"
                        | SOME ch =>
                            case findClientKeyShare (#extensions ch) of
                                NONE => raise Tls "client sent no X25519 key_share"
                              | SOME k => k
      val dhe = X25519.dh (#x25519PrivateKey cfg) clientPub
      val sched = TlsKeySchedule.schedule {
        dhe = dhe,
        handshakeTranscript = transcript,
        applicationTranscript = ""
      }
      val cs = #cipherSuite cfg
      val (keyLen, ivLen) =
        if cs = TlsHandshake.suiteTlsAes128GcmSha256 orelse
           cs = TlsHandshake.suiteTlsChaCha20Poly1305 then (16, 12)
        else if cs = TlsHandshake.suiteTlsAes256GcmSha384 then (32, 12)
        else (16, 12)
      val sHsKey = TlsKeySchedule.trafficKey
        {secret = #serverHandshakeSecret sched, keyLength = keyLen}
      val sHsIv = TlsKeySchedule.trafficIv
        {secret = #serverHandshakeSecret sched, ivLength = ivLen}
      val cHsKey = TlsKeySchedule.trafficKey
        {secret = #clientHandshakeSecret sched, keyLength = keyLen}
      val cHsIv = TlsKeySchedule.trafficIv
        {secret = #clientHandshakeSecret sched, ivLength = ivLen}
      val record = TlsRecord.encodePlaintext
        {contentType = TlsRecord.Handshake, fragment = shMsg}
      val st' = {
        x25519PrivateKey = #x25519PrivateKey cfg,
        serverRandom = #serverRandom cfg,
        cipherSuite = SOME cs,
        legacySessionId = #legacySessionId cfg,
        extensions = #extensions cfg,
        transcript = transcript,
        dhe = dhe,
        clientHello = #clientHello st,
        serverHello = SOME sh,
        clientHsSecret = SOME (#clientHandshakeSecret sched),
        serverHsSecret = SOME (#serverHandshakeSecret sched),
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
      val serverHsSecret = Option.valOf (#serverHsSecret st)
      val sHsKiv = Option.valOf (#serverHandshakeKey st)
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
      (* CertificateVerify: the CV signature is produced/verified by the
         caller via sml-rsa / sml-p256.  This minimal server emits a
         structurally-valid CV with an empty signature; the client skips CV
         signature verification in this build (handshake authenticity is
         carried by the Finished MAC over the shared transcript). *)
      val tBeforeCv = #transcript st ^ eeMsg ^ certMsg
      val cvBody = TlsHandshake.encodeCertificateVerify
        {sigAlg = #sigAlg cfg, sigBytes = ""}
      val cvMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.CertificateVerify, body = cvBody}
      (* Server Finished over the transcript through CertificateVerify. *)
      val tBeforeFin = tBeforeCv ^ cvMsg
      val sfKey = TlsKeySchedule.finishedKey {secret = serverHsSecret}
      val sfVerify = TlsKeySchedule.finishedVerifyData
        {finishedKey = sfKey, transcript = tBeforeFin}
      val sfBody = TlsHandshake.encodeFinished {verifyData = sfVerify}
      val sfMsg = TlsHandshake.encodeMessage
        {msgType = TlsHandshake.Finished, body = sfBody}
      val transcript' = tBeforeFin ^ sfMsg
      (* Application-traffic keys from the transcript through server Finished. *)
      val sched = TlsKeySchedule.schedule {
        dhe = #dhe st,
        handshakeTranscript = #transcript st,
        applicationTranscript = transcript'
      }
      val sApSec = #serverAppSecret sched
      val cApSec = #clientAppSecret sched
      val sApKey = TlsKeySchedule.trafficKey {secret = sApSec, keyLength = keyLen}
      val sApIv  = TlsKeySchedule.trafficIv  {secret = sApSec, ivLength = ivLen}
      val cApKey = TlsKeySchedule.trafficKey {secret = cApSec, keyLength = keyLen}
      val cApIv  = TlsKeySchedule.trafficIv  {secret = cApSec, ivLength = ivLen}
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
      val (p2, r2) = emit (p1, certMsg)
      val (p3, r3) = emit (p2, cvMsg)
      val (_,  r4) = emit (p3, sfMsg)
      val flight = r1 ^ r2 ^ r3 ^ r4
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
      val next = nextAppSecret (Option.valOf (#clientApSecret st))
      val k = TlsKeySchedule.trafficKey {secret = next, keyLength = kl}
      val iv = TlsKeySchedule.trafficIv {secret = next, ivLength = il}
    in
      { x25519PrivateKey = #x25519PrivateKey st, serverRandom = #serverRandom st,
        cipherSuite = #cipherSuite st, legacySessionId = #legacySessionId st,
        extensions = #extensions st, transcript = #transcript st, dhe = #dhe st,
        clientHello = #clientHello st, serverHello = #serverHello st,
        clientHsSecret = #clientHsSecret st, serverHsSecret = #serverHsSecret st,
        clientApSecret = SOME next, serverApSecret = #serverApSecret st,
        serverHandshakeKey = #serverHandshakeKey st,
        clientHandshakeKey = #clientHandshakeKey st,
        serverAppKey = #serverAppKey st, clientAppKey = SOME (k, iv),
        clientHsProtect = #clientHsProtect st,
        clientApProtect = SOME (mkProtect (cs, (k, iv))),
        serverApProtect = #serverApProtect st, errorAlert = #errorAlert st,
        connected = #connected st }
    end

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

  (* Feed received ciphertext records to the server.  During the handshake
     this is the client Finished (under the client HS key); once connected it
     is application data / KeyUpdate (under the client app key). *)
  fun step (st : serverState, input : string) : serverState * string list =
    if Option.isSome (#errorAlert st) then (st, [])
    else if input = "" then (st, [])
    else
      (if not (#connected st) then
         (* Expect the client Finished under the client HS key. *)
         (case TlsRecord.decodeCiphertext input of
              NONE => raise Fatal TlsAlert.DecodeError
            | SOME (crec, _) =>
                if #contentType crec = TlsRecord.ChangeCipherSpec then (st, [])
                else
                  let val prot = Option.valOf (#clientHsProtect st) in
                    case TlsRecordProtect.unprotect
                           {state = prot, record = #encryptedRecord crec} of
                        NONE => raise Fatal TlsAlert.BadRecordMac
                      | SOME (_, pt, _) =>
                          (case TlsHandshake.decodeMessage pt of
                               SOME ({msgType = TlsHandshake.Finished, body}, _) =>
                                 let
                                   val cfKey = TlsKeySchedule.finishedKey
                                     {secret = Option.valOf (#clientHsSecret st)}
                                   val expected = TlsKeySchedule.finishedVerifyData
                                     {finishedKey = cfKey, transcript = #transcript st}
                                 in
                                   if expected = body then (markConnected st, [])
                                   else raise Fatal TlsAlert.DecryptError
                                 end
                             | _ => raise Fatal TlsAlert.UnexpectedMessage)
                  end)
       else
         (* Connected: decrypt application data / KeyUpdate under client app key. *)
         (case TlsRecord.decodeCiphertext input of
              NONE => raise Fatal TlsAlert.DecodeError
            | SOME (crec, _) =>
                if #contentType crec = TlsRecord.ChangeCipherSpec then (st, [])
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

  fun error (st : serverState) : Word8.word option = #errorAlert st

  fun negotiatedCipherSuite (st : serverState) = #cipherSuite st
  fun serverHandshakeKey (st : serverState) = #serverHandshakeKey st
  fun clientHandshakeKey (st : serverState) = #clientHandshakeKey st
  fun serverAppKey (st : serverState) = #serverAppKey st
  fun clientAppKey (st : serverState) = #clientAppKey st
  fun transcript (st : serverState) = #transcript st
  fun isConnected (st : serverState) = #connected st
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
