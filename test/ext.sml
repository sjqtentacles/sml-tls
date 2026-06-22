(* Tests for extension codecs + negotiation (Track A3, Phase 2 parallel half).

   RFC 8448 publishes the exact ClientHello and ServerHello extension
   blocks; we build == published and decode == structure, byte-for-byte.
   Plus negotiation matrices (empty intersection -> NONE), malformed-body
   cases (truncated length, trailing junk -> NONE), and the downgrade-
   protection sentinel constants.

   This file is self-contained for hex helpers; the A3 subagent owns it
   exclusively. *)

structure ExtTests =
struct
  open Harness

  (* ---- Hex helpers (copied from test.sml so this file is standalone) ---- *)
  fun nib c =
    if c >= #"0" andalso c <= #"9" then Char.ord c - Char.ord #"0"
    else if c >= #"a" andalso c <= #"f" then Char.ord c - Char.ord #"a" + 10
    else if c >= #"A" andalso c <= #"F" then Char.ord c - Char.ord #"A" + 10
    else ~1

  fun fromHex s =
    let
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

  fun bytes [] = ""
    | bytes (n :: ns) = String.str (Char.chr n) ^ bytes ns

  fun str2 a b = bytes [a, b]

  fun checkBytes (name, expected, actual) =
    if bytesEq (expected, actual) then check name true
    else
      let val () = print ("  FAIL - " ^ name ^ ": " ^ toHex expected ^ " <> " ^ toHex actual ^ "\n")
      in check name false end

  (* ---- RFC 8448 ClientHello extension-body vectors ----
     Each is the body of an extension (i.e. the data field of
     TlsHandshake.extension), NOT including the 4-byte extType+length
     framing produced by TlsHandshake.encodeExtensions. *)

  (* server_name / SNI host_name = "server". RFC 8448 extension block:
       00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72
     extType=0000, extLen=000b (11), body = 00 09 00 00 06 73 65 72 76 65 72
     - 00 09 : ServerNameList length (9 bytes follow)
     - 00    : name_type host_name
     - 00 06 : HostName length (6)
     - "server" *)
  val sniBody = fromHex "0009000006736572766572"
  val sniName = "server"

  (* supported_groups. RFC 8448:
       00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04
     extType=000a, extLen=0014 (20), body = 00 12 00 1d 00 17 00 18 00 19 01 00
     01 01 01 02 01 03 01 04
     - 00 12 : NamedGroupList length (18)
     - 9 named groups (2 bytes each): 001d 0017 0018 0019 0100 0101 0102 0103 0104. *)
  val supportedGroupsBody = fromHex
    "0012001d00170018001901000101010201030104"
  val supportedGroupsList = [
    TlsHandshake.groupX25519,       (* 0x001d *)
    0wx0017, 0wx0018, 0wx0019,
    0wx0100, 0wx0101, 0wx0102, 0wx0103, 0wx0104
  ]

  (* signature_algorithms. RFC 8448:
       00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06
       04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02
     extType=000d, extLen=0020 (32), body = 00 1e 04 03 ... 02 02
     - 00 1e : SignatureSchemeList length (30)
     - 15 schemes (2 bytes each): 0403 0503 0603 0203 0804 0805 0806
       0401 0501 0601 0201 0402 0502 0602 0202. *)
  val sigAlgsBody = fromHex
    "001e040305030603020308040805080604010501060102010402050206020202"
  val sigAlgsList = [
    TlsHandshake.sigEcdsaSecp256r1Sha256,  (* 0x0403 *)
    0wx0503, 0wx0603, 0wx0203,
    TlsHandshake.sigRsaPssRsaSha256,       (* 0x0804 *)
    TlsHandshake.sigRsaPssRsaSha384,       (* 0x0805 *)
    TlsHandshake.sigRsaPssRsaSha512,       (* 0x0806 *)
    0wx0401, 0wx0501, 0wx0601, 0wx0201,
    0wx0402, 0wx0502, 0wx0602, 0wx0202
  ]

  (* key_share (ClientHello form). RFC 8448:
       00 33 00 26 00 24 00 1d 00 20
       99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe
       b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c
     extType=0033, extLen=0026 (38), body = 00 24 00 1d 00 20 + 32-byte key
     - 00 24 : KeyShareEntry list length (36)
     - 00 1d : group x25519
     - 00 20 : key length (32)
     - 32 bytes of key. *)
  val keyShareCHBody = fromHex
    "0024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
  val keyShareCHKeyExchange = fromHex
    "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
  val keyShareCHList = [
    {group = TlsHandshake.groupX25519, keyExchange = keyShareCHKeyExchange}
  ] : TlsExtensions.keyShareEntry list

  (* supported_versions (ClientHello form). RFC 8448:
       00 2b 00 03 02 03 04
     extType=002b, extLen=0003 (3), body = 02 03 04
     - 02 : 1-byte list length (2)
     - 03 04 : TLS 1.3 (0x0304) *)
  val supportedVersionsCHBody = fromHex "020304"
  val supportedVersionsCHList = [0wx0304]

  (* ---- RFC 8448 ServerHello extension-body vectors ---- *)

  (* key_share (ServerHello form: no outer list-length prefix). RFC 8448:
       00 1d 00 20
       9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10
       a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15
     - 00 1d : group x25519
     - 00 20 : key length (32)
     - 32 bytes of key *)
  val keyShareSHBody = fromHex
    "001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"
  val keyShareSHKeyExchange = fromHex
    "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"
  val keyShareSHEntry = {
    group = TlsHandshake.groupX25519,
    keyExchange = keyShareSHKeyExchange
  } : TlsExtensions.keyShareEntry

  (* supported_versions (ServerHello form: just the 2-byte selected
     version, no length prefix). RFC 8448: 03 04 *)
  val supportedVersionsSHBody = fromHex "0304"
  val supportedVersionsSHSelected = 0wx0304

  (* ---- Downgrade sentinels (RFC 8446 §4.1.3) ----
     Last 8 bytes of ServerHello.random that a TLS 1.2 / 1.1 server sets
     to signal the negotiated version. A TLS 1.3 client MUST abort. *)
  val sentinelTls12 = bytes [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
  val sentinelTls11 = bytes [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

  fun run () =
    let
      val () = section "Extensions (A3): key_share CH codec"
      (* Build == RFC 8448 published bytes. *)
      val () = checkBytes ("encodeKeyShareCH == RFC8448",
                           keyShareCHBody,
                           TlsExtensions.encodeKeyShareCH keyShareCHList)
      (* Decode == structure. *)
      val () = case TlsExtensions.decodeKeyShareCH keyShareCHBody of
                   NONE => checkBool "decodeKeyShareCH returns SOME" (true, false)
                 | SOME xs =>
                     (checkBool ("decodeKeyShareCH group") (true,
                        #group (List.hd xs) = TlsHandshake.groupX25519);
                      checkBytes ("decodeKeyShareCH keyExchange",
                        keyShareCHKeyExchange, #keyExchange (List.hd xs));
                      checkInt "decodeKeyShareCH list length" (1, List.length xs))
      (* Round-trip a multi-entry list. *)
      val multiList = [
        {group = 0wx0017, keyExchange = "abcdef"},
        {group = TlsHandshake.groupX25519, keyExchange = keyShareCHKeyExchange}
      ] : TlsExtensions.keyShareEntry list
      val () = case TlsExtensions.decodeKeyShareCH
                     (TlsExtensions.encodeKeyShareCH multiList) of
                   NONE => checkBool "key_share CH multi round-trip" (true, false)
                 | SOME xs =>
                     checkBool ("key_share CH multi round-trip")
                       (true, xs = multiList)

      val () = section "Extensions (A3): key_share SH codec"
      val () = checkBytes ("encodeKeyShareSH == RFC8448",
                           keyShareSHBody,
                           TlsExtensions.encodeKeyShareSH keyShareSHEntry)
      val () = case TlsExtensions.decodeKeyShareSH keyShareSHBody of
                   NONE => checkBool "decodeKeyShareSH returns SOME" (true, false)
                 | SOME e =>
                     (checkBool ("decodeKeyShareSH group") (true,
                        #group e = TlsHandshake.groupX25519);
                      checkBytes ("decodeKeyShareSH keyExchange",
                        keyShareSHKeyExchange, #keyExchange e))
      val () = checkBool ("encodeKeyShareSH o decodeKeyShareSH == id")
        (true, TlsExtensions.decodeKeyShareSH keyShareSHBody = SOME keyShareSHEntry)

      val () = section "Extensions (A3): supported_versions codec"
      val () = checkBytes ("encodeSupportedVersionsCH == RFC8448",
                           supportedVersionsCHBody,
                           TlsExtensions.encodeSupportedVersionsCH supportedVersionsCHList)
      val () = case TlsExtensions.decodeSelectedVersionSH supportedVersionsSHBody of
                   NONE => checkBool "decodeSelectedVersionSH returns SOME" (true, false)
                 | SOME v =>
                     checkBool ("decodeSelectedVersionSH == 0x0304") (true,
                       v = supportedVersionsSHSelected)
      val () = case TlsExtensions.decodeSelectedVersionSH (fromHex "0304") of
                   SOME v =>
                     checkBool ("selected version value") (true, v = 0wx0304)
                 | NONE => checkBool "selected version parses" (true, false)

      val () = section "Extensions (A3): supported_groups codec"
      val () = checkBytes ("encodeSupportedGroups == RFC8448",
                           supportedGroupsBody,
                           TlsExtensions.encodeSupportedGroups supportedGroupsList)
      val () = case TlsExtensions.decodeSupportedGroups supportedGroupsBody of
                   NONE => checkBool "decodeSupportedGroups returns SOME" (true, false)
                 | SOME gs =>
                     checkBool ("decodeSupportedGroups == list") (true, gs = supportedGroupsList)
      val () = checkBool ("encodeSupportedGroups o decodeSupportedGroups == id")
        (true, TlsExtensions.decodeSupportedGroups
                 (TlsExtensions.encodeSupportedGroups supportedGroupsList)
               = SOME supportedGroupsList)

      val () = section "Extensions (A3): signature_algorithms codec"
      val () = checkBytes ("encodeSignatureAlgorithms == RFC8448",
                           sigAlgsBody,
                           TlsExtensions.encodeSignatureAlgorithms sigAlgsList)
      val () = case TlsExtensions.decodeSignatureAlgorithms sigAlgsBody of
                   NONE => checkBool "decodeSignatureAlgorithms returns SOME" (true, false)
                 | SOME xs =>
                     checkBool ("decodeSignatureAlgorithms == list") (true, xs = sigAlgsList)
      val () = checkBool ("encodeSignatureAlgorithms o decodeSignatureAlgorithms == id")
        (true, TlsExtensions.decodeSignatureAlgorithms
                 (TlsExtensions.encodeSignatureAlgorithms sigAlgsList)
               = SOME sigAlgsList)

      val () = section "Extensions (A3): server_name (SNI) codec"
      val () = checkBytes ("encodeServerName == RFC8448",
                           sniBody,
                           TlsExtensions.encodeServerName sniName)
      val () = case TlsExtensions.decodeServerName sniBody of
                   NONE => checkBool "decodeServerName returns SOME" (true, false)
                 | SOME n =>
                     checkBool ("decodeServerName == \"server\"") (true, n = sniName)
      val () = checkBool ("encodeServerName o decodeServerName == id")
        (true, TlsExtensions.decodeServerName
                 (TlsExtensions.encodeServerName sniName) = SOME sniName)
      (* A longer hostname round-trips too. *)
      val () = case TlsExtensions.decodeServerName
                     (TlsExtensions.encodeServerName "example.com") of
                   SOME n => checkBool ("SNI example.com round-trip") (true, n = "example.com")
                 | NONE => checkBool "SNI example.com round-trip" (true, false)

      val () = section "Extensions (A3): ALPN codec"
      val alpnProtos = ["http/1.1"]
      val alpnBody = fromHex "000908687474702f312e31"
      val () = checkBytes ("encodeAlpn == published",
                           alpnBody,
                           TlsExtensions.encodeAlpn alpnProtos)
      val () = case TlsExtensions.decodeAlpn alpnBody of
                   NONE => checkBool "decodeAlpn returns SOME" (true, false)
                 | SOME ps =>
                     checkBool ("decodeAlpn == [http/1.1]") (true, ps = alpnProtos)
      val () = checkBool ("encodeAlpn o decodeAlpn == id (multi)")
        (true, TlsExtensions.decodeAlpn
                 (TlsExtensions.encodeAlpn ["h2", "http/1.1"])
               = SOME ["h2", "http/1.1"])

      val () = section "Extensions (A3): negotiation matrices"
      (* negotiateVersion: server policy is TLS 1.3 only (0x0304); return
         it if the client offers it, else NONE. *)
      val () = checkBool ("negotiateVersion: client has 0x0304")
        (true, TlsExtensions.negotiateVersion [0wx0303, 0wx0304] = SOME 0wx0304)
      val () = checkBool ("negotiateVersion: empty intersection")
        (true, TlsExtensions.negotiateVersion [0wx0303, 0wx0302] = NONE)
      val () = checkBool ("negotiateVersion: empty client list")
        (true, TlsExtensions.negotiateVersion [] = NONE)

      (* negotiateGroup: first client-preferred group that the server also
         supports. *)
      val () = checkBool ("negotiateGroup: matching group")
        (true, TlsExtensions.negotiateGroup {
                  clientShares = [{group = TlsHandshake.groupX25519,
                                   keyExchange = "k"}],
                  serverGroups = [TlsHandshake.groupX25519]
                } = SOME TlsHandshake.groupX25519)
      val () = checkBool ("negotiateGroup: no overlap")
        (true, TlsExtensions.negotiateGroup {
                  clientShares = [{group = 0wx0017, keyExchange = "k"}],
                  serverGroups = [TlsHandshake.groupX25519]
                } = NONE)
      val () = checkBool ("negotiateGroup: empty client shares")
        (true, TlsExtensions.negotiateGroup {
                  clientShares = [],
                  serverGroups = [TlsHandshake.groupX25519]
                } = NONE)
      val () = checkBool ("negotiateGroup: picks client-preferred on overlap")
        (true, TlsExtensions.negotiateGroup {
                  clientShares = [{group = 0wx0017, keyExchange = "a"},
                                  {group = TlsHandshake.groupX25519,
                                   keyExchange = "b"}],
                  serverGroups = [TlsHandshake.groupX25519, 0wx0017]
                } = SOME 0wx0017)

      (* negotiateSigAlg: first client-preferred scheme that the server
         also supports. *)
      val () = checkBool ("negotiateSigAlg: overlap")
        (true, TlsExtensions.negotiateSigAlg {
                  client = [TlsHandshake.sigEcdsaSecp256r1Sha256,
                            TlsHandshake.sigRsaPssRsaSha256],
                  server = [TlsHandshake.sigRsaPssRsaSha256]
                } = SOME TlsHandshake.sigRsaPssRsaSha256)
      val () = checkBool ("negotiateSigAlg: no overlap -> NONE")
        (true, TlsExtensions.negotiateSigAlg {
                  client = [TlsHandshake.sigEcdsaSecp256r1Sha256],
                  server = [TlsHandshake.sigRsaPssRsaSha256]
                } = NONE)
      val () = checkBool ("negotiateSigAlg: empty client -> NONE")
        (true, TlsExtensions.negotiateSigAlg {
                  client = [],
                  server = [TlsHandshake.sigRsaPssRsaSha256]
                } = NONE)

      val () = section "Extensions (A3): malformed bodies -> NONE"
      (* key_share CH: truncated length, trailing junk, zero-length. *)
      val () = checkBool ("decodeKeyShareCH truncated -> NONE")
        (true, TlsExtensions.decodeKeyShareCH (fromHex "0026") = NONE)
      val () = checkBool ("decodeKeyShareCH entry trunc -> NONE")
        (true, TlsExtensions.decodeKeyShareCH (fromHex "0004001d") = NONE)
      val () = checkBool ("decodeKeyShareCH trailing junk -> NONE")
        (true, TlsExtensions.decodeKeyShareCH
                 (keyShareCHBody ^ fromHex "00") = NONE)
      val () = checkBool ("decodeKeyShareCH empty -> NONE")
        (true, TlsExtensions.decodeKeyShareCH "" = NONE)
      val () = checkBool ("decodeKeyShareCH zero-len key -> NONE")
        (true, TlsExtensions.decodeKeyShareCH (fromHex "0004001d0000") = NONE)

      (* key_share SH. *)
      val () = checkBool ("decodeKeyShareSH truncated -> NONE")
        (true, TlsExtensions.decodeKeyShareSH (fromHex "001d") = NONE)
      val () = checkBool ("decodeKeyShareSH trailing junk -> NONE")
        (true, TlsExtensions.decodeKeyShareSH
                 (keyShareSHBody ^ fromHex "00") = NONE)
      val () = checkBool ("decodeKeyShareSH empty -> NONE")
        (true, TlsExtensions.decodeKeyShareSH "" = NONE)

      (* supported_versions SH. *)
      val () = checkBool ("decodeSelectedVersionSH truncated -> NONE")
        (true, TlsExtensions.decodeSelectedVersionSH (fromHex "03") = NONE)
      val () = checkBool ("decodeSelectedVersionSH trailing junk -> NONE")
        (true, TlsExtensions.decodeSelectedVersionSH (fromHex "030400") = NONE)
      val () = checkBool ("decodeSelectedVersionSH empty -> NONE")
        (true, TlsExtensions.decodeSelectedVersionSH "" = NONE)

      (* supported_groups. *)
      val () = checkBool ("decodeSupportedGroups truncated -> NONE")
        (true, TlsExtensions.decodeSupportedGroups (fromHex "0002") = NONE)
      val () = checkBool ("decodeSupportedGroups trailing junk -> NONE")
        (true, TlsExtensions.decodeSupportedGroups
                 (supportedGroupsBody ^ fromHex "00") = NONE)
      val () = checkBool ("decodeSupportedGroups empty -> NONE")
        (true, TlsExtensions.decodeSupportedGroups "" = NONE)
      val () = checkBool ("decodeSupportedGroups odd-length list -> NONE")
        (true, TlsExtensions.decodeSupportedGroups (fromHex "00010001") = NONE)

      (* signature_algorithms. *)
      val () = checkBool ("decodeSignatureAlgorithms truncated -> NONE")
        (true, TlsExtensions.decodeSignatureAlgorithms (fromHex "0002") = NONE)
      val () = checkBool ("decodeSignatureAlgorithms trailing junk -> NONE")
        (true, TlsExtensions.decodeSignatureAlgorithms
                 (sigAlgsBody ^ fromHex "00") = NONE)
      val () = checkBool ("decodeSignatureAlgorithms empty -> NONE")
        (true, TlsExtensions.decodeSignatureAlgorithms "" = NONE)

      (* server_name. *)
      val () = checkBool ("decodeServerName truncated -> NONE")
        (true, TlsExtensions.decodeServerName (fromHex "000b") = NONE)
      val () = checkBool ("decodeServerName trailing junk -> NONE")
        (true, TlsExtensions.decodeServerName (sniBody ^ fromHex "00") = NONE)
      val () = checkBool ("decodeServerName empty -> NONE")
        (true, TlsExtensions.decodeServerName "" = NONE)
      val () = checkBool ("decodeServerName non-host_name type -> NONE")
        (true, TlsExtensions.decodeServerName (fromHex "000b0001000006") = NONE)

      (* ALPN. *)
      val () = checkBool ("decodeAlpn truncated -> NONE")
        (true, TlsExtensions.decodeAlpn (fromHex "0009") = NONE)
      val () = checkBool ("decodeAlpn trailing junk -> NONE")
        (true, TlsExtensions.decodeAlpn (alpnBody ^ fromHex "00") = NONE)
      val () = checkBool ("decodeAlpn empty -> NONE")
        (true, TlsExtensions.decodeAlpn "" = NONE)

      val () = section "Extensions (A3): downgrade sentinels"
      val () = checkBytes ("downgradeSentinelTls12 == 8 bytes",
                           sentinelTls12,
                           TlsExtensions.downgradeSentinelTls12)
      val () = checkBytes ("downgradeSentinelTls11 == 8 bytes",
                           sentinelTls11,
                           TlsExtensions.downgradeSentinelTls11)
      val () = checkInt "sentinel Tls12 length" (8, String.size TlsExtensions.downgradeSentinelTls12)
      val () = checkInt "sentinel Tls11 length" (8, String.size TlsExtensions.downgradeSentinelTls11)
      val () = checkBool ("sentinels differ in last byte")
        (true, TlsExtensions.downgradeSentinelTls12 <> TlsExtensions.downgradeSentinelTls11)
    in
      ()
    end
end
