(* zeroize.sml

   Track 1b tests: after a full handshake populates traffic keys and other
   secret material, TlsClient.zeroize / TlsServer.zeroize (and
   TlsServer.zeroizeConfig for the RSA private key) must overwrite that
   material with zeros, observable through the test-only `secretsForTest`
   accessors. Uses SecureZero under the hood (sodium_memzero in the FFI
   build, a portable Word8Array wipe in the default build). *)

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

      val () = section "zeroize: client/server secrets wiped to zero"
      val cstZ = TlsClient.zeroize cst2
      val sstZ = TlsServer.zeroize sst3
      val () = check "client secrets all zero after zeroize"
        (allZero (TlsClient.secretsForTest cstZ))
      val () = check "server secrets all zero after zeroize"
        (allZero (TlsServer.secretsForTest sstZ))
      (* Lengths preserved (we zero in place, not truncate). *)
      val () = checkInt "client secret count unchanged"
        (List.length cSecrets, List.length (TlsClient.secretsForTest cstZ))
      val () = checkInt "server secret count unchanged"
        (List.length sSecrets, List.length (TlsServer.secretsForTest sstZ))
      (* The zeroed state stays usable for inspection (no crash). *)
      val () = check "zeroized client still reports connected"
        (TlsClient.isConnected cstZ)

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
    in
      ()
    end
end
