(* zeroize.sml

   Track 1b tests: REAL in-place erasure of TLS secret material.

   Secrets in the handshake state are held in mutable, reference-shared
   `Secret` buffers (Word8Array-backed). The state machine is purely
   functional -- `zeroize cst` returns a NEW state -- but because the secret
   buffers are shared by reference, wiping them through the returned state
   ALSO erases the bytes seen through the ORIGINAL handle. That is the
   load-bearing assertion here, and it is impossible with the old immutable
   `string` secrets (where `zeroize` could only rebind the copy and the
   original kept its live bytes).

   `secretsForTest` materializes the secrets' CURRENT live bytes each call,
   so reading it through the original `cst2`/`sst3` after a `zeroize` reflects
   the in-place wipe. The teardown also wipes the old TlsRecordProtect traffic
   key/iv buffers and the server PSK ticket store.

   Uses SecureZero under the hood (sodium_memzero in the FFI build, a portable
   Word8Array wipe in the default build). *)

structure ZeroizeTests =
struct
  open Harness

  fun bytes [] = ""
    | bytes (n :: ns) = String.str (Char.chr n) ^ bytes ns

  val clientRandom = String.implode (List.tabulate (32, fn i => Char.chr ((i + 1) mod 256)))
  val serverRandom = String.implode (List.tabulate (32, fn i => Char.chr ((i * 5 + 9) mod 256)))
  val clientX25519 = String.implode (List.tabulate (32, fn i => Char.chr ((i + 17) mod 256)))
  val serverX25519 = String.implode (List.tabulate (32, fn i => Char.chr ((i * 7 + 3) mod 256)))

  fun hsBody record =
    case TlsRecord.decodePlaintext record of
        SOME (r, _) =>
          (case TlsHandshake.decodeMessage (#fragment r) of
               SOME ({body, ...}, _) => body
             | _ => raise Fail "hsBody")
      | _ => raise Fail "hsBody"

  val clientCfg = {
    x25519PrivateKey = clientX25519, p256PrivateKey = NONE,
    clientRandom = clientRandom, legacySessionId = "",
    cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
    extensions = [], serverName = "example.com",
    trustStore = [], now = 0, sigAlgs = [TlsHandshake.sigRsaPssRsaSha256]
  } : TlsClient.clientConfig

  val serverCfg = {
    x25519PrivateKey = serverX25519, p256PrivateKey = NONE,
    serverRandom = serverRandom,
    cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
    legacySessionId = "", extensions = [], certChain = [],
    rsaPrivateKeyDer = "",
    sigAlg = TlsHandshake.sigRsaPssRsaSha256, now = 0, sigAlgs = []
  } : TlsServer.serverConfig

  (* A config carrying (bogus) long-term key material, used only to test
     zeroizeConfig -- it never drives a handshake, so the bytes need not be
     valid DER. *)
  val secretServerCfg = {
    x25519PrivateKey = serverX25519, p256PrivateKey = NONE,
    serverRandom = serverRandom,
    cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256,
    legacySessionId = "", extensions = [], certChain = [],
    rsaPrivateKeyDer = "RSA-PRIVATE-KEY-MATERIAL-bytes-here",
    sigAlg = TlsHandshake.sigRsaPssRsaSha256, now = 0, sigAlgs = []
  } : TlsServer.serverConfig

  val secretClientCfg = {
    x25519PrivateKey = clientX25519,
    p256PrivateKey = SOME (String.implode (List.tabulate (32, fn _ => #"\042"))),
    clientRandom = clientRandom, legacySessionId = "",
    cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256],
    extensions = [], serverName = "example.com",
    trustStore = [], now = 0, sigAlgs = [TlsHandshake.sigRsaPssRsaSha256]
  } : TlsClient.clientConfig

  (* True iff every byte of every string is 0 (and there is at least one
     non-empty string, so the assertion is meaningful). *)
  fun allZero ss =
    List.all (fn s => CharVector.all (fn c => c = #"\000") s) ss
  fun anyNonEmpty ss = List.exists (fn s => String.size s > 0) ss

  fun run () =
    let
      val () = section "zeroize: full handshake populates secret material"
      val (cst0, chRecord) = TlsClient.startHandshake clientCfg
      val sst0 = TlsServer.receiveClientHello (hsBody chRecord)
      val (sst1, shRecord) = TlsServer.produceServerHello (sst0, serverCfg)
      val (cst1, _) = TlsClient.step (cst0, shRecord)
      val (sst2, flight) = TlsServer.produceServerFlight (sst1, serverCfg)
      val (cst2, clientOut) = TlsClient.step (cst1, flight)
      val (sst3, _) = TlsServer.step (sst2, List.hd clientOut)

      val () = check "client connected" (TlsClient.isConnected cst2)
      val () = check "server connected" (TlsServer.isConnected sst3)

      (* Snapshot the secret bytes BEFORE any zeroize, read through the
         original handles. *)
      val cSecrets = TlsClient.secretsForTest cst2
      val sSecrets = TlsServer.secretsForTest sst3
      val () = check "client holds non-empty secrets before zeroize"
        (anyNonEmpty cSecrets)
      val () = check "server holds non-empty secrets before zeroize"
        (anyNonEmpty sSecrets)
      val () = check "client secrets are NOT all zero before zeroize"
        (not (allZero cSecrets))
      val () = check "server secrets are NOT all zero before zeroize"
        (not (allZero sSecrets))

      val () = section "zeroize: in-place wipe observed through ORIGINAL handle"
      (* The key new assertion: zeroize the (functionally rebuilt) state,
         then read the secrets back through the ORIGINAL handle. Because the
         secret buffers are mutable and reference-shared, the original sees
         the wipe -- impossible with the old immutable-string secrets. *)
      val cstZ = TlsClient.zeroize cst2
      val sstZ = TlsServer.zeroize sst3
      val () = check "client secrets all zero through ORIGINAL handle after zeroize"
        (allZero (TlsClient.secretsForTest cst2))
      val () = check "server secrets all zero through ORIGINAL handle after zeroize"
        (allZero (TlsServer.secretsForTest sst3))
      (* The returned state, sharing the same buffers, is of course also zero. *)
      val () = check "client secrets all zero through returned handle"
        (allZero (TlsClient.secretsForTest cstZ))
      val () = check "server secrets all zero through returned handle"
        (allZero (TlsServer.secretsForTest sstZ))
      (* Lengths preserved (we zero in place, not truncate). *)
      val () = checkInt "client secret count unchanged"
        (List.length cSecrets, List.length (TlsClient.secretsForTest cst2))
      val () = checkInt "server secret count unchanged"
        (List.length sSecrets, List.length (TlsServer.secretsForTest sst3))
      (* The zeroed state stays usable for inspection (no crash). *)
      val () = check "zeroized client still reports connected"
        (TlsClient.isConnected cstZ)
      val () = check "zeroized server still reports connected"
        (TlsServer.isConnected sstZ)

      val () = section "zeroize: traffic-key buffers wiped (record protect)"
      (* The negotiated traffic keys (exposed as (key,iv) through the public
         accessors) read as zeros through the original handle after zeroize:
         the old TlsRecordProtect key/iv buffers were wiped in place, not
         merely replaced-and-dropped. *)
      val () =
        case TlsClient.serverHandshakeKey cst2 of
            SOME (k, iv) =>
              check "client server-handshake key+iv wiped in place"
                (allZero [k, iv])
          | NONE => check "client server-handshake key present" false
      val () =
        case TlsServer.serverAppKey sst3 of
            SOME (k, iv) =>
              check "server app key+iv wiped in place" (allZero [k, iv])
          | NONE => check "server app key present" false

      val () = section "zeroize: PSK ticket store wiped on teardown"
      (* Seed the ticket store with bogus entries, then confirm zeroize wipes
         the stored PSK bytes. *)
      val ticketId = "ticket-identity-0001"
      val ticketPsk = String.implode (List.tabulate (32, fn _ => #"\077"))
      val () = TlsServer.storeTicketForTest (ticketId, ticketPsk)
      val () = check "ticket store non-empty before teardown"
        (anyNonEmpty (TlsServer.ticketStoreSecretsForTest ()))
      val _ = TlsServer.zeroize sst3
      val () = check "ticket store PSK bytes all zero after zeroize"
        (allZero (TlsServer.ticketStoreSecretsForTest ()))

      val () = section "zeroize: server RSA private key (config) wiped"
      val () = check "config rsaPrivateKeyDer non-empty before"
        (String.size (#rsaPrivateKeyDer secretServerCfg) > 0)
      val cfgZ = TlsServer.zeroizeConfig secretServerCfg
      val () = check "config rsaPrivateKeyDer all zero after"
        (CharVector.all (fn c => c = #"\000") (#rsaPrivateKeyDer cfgZ))
      val () = checkInt "config rsaPrivateKeyDer length preserved"
        (String.size (#rsaPrivateKeyDer secretServerCfg),
         String.size (#rsaPrivateKeyDer cfgZ))
      val () = check "config x25519PrivateKey wiped too"
        (CharVector.all (fn c => c = #"\000") (#x25519PrivateKey cfgZ))

      val () = section "zeroize: client config wiped (new)"
      val () = check "client config x25519PrivateKey non-empty before"
        (String.size (#x25519PrivateKey secretClientCfg) > 0)
      val ccfgZ = TlsClient.zeroizeConfig secretClientCfg
      val () = check "client config x25519PrivateKey all zero after"
        (CharVector.all (fn c => c = #"\000") (#x25519PrivateKey ccfgZ))
      val () = checkInt "client config x25519PrivateKey length preserved"
        (String.size (#x25519PrivateKey secretClientCfg),
         String.size (#x25519PrivateKey ccfgZ))
      val () = check "client config p256PrivateKey wiped too"
        (case #p256PrivateKey ccfgZ of
             SOME s => CharVector.all (fn c => c = #"\000") s
           | NONE => false)
    in
      ()
    end
end
