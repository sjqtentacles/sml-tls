(* Tests for certificate-chain validation (Track A2, Phase 3).

   Golden-chain fixtures (valid, expired, wrong-name, untrusted-CA,
   path-length-violation, bad-signature) are generated offline by a
   committed openssl script (test/fixtures/certs/gen.sh) and committed as
   DER/PEM under `test/fixtures/certs/`. Each fixture asserts the exact
   accept/alert outcome. No network access at test time.

   This file is self-contained for hex helpers; the A2 subagent owns it
   exclusively. *)

structure CertTests =
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

  (* ---- File reading ----
     Reads a binary file (relative to the repo root, where the test binary
     is run) as a raw byte string. Works under both MLton and Poly/ML. *)
  fun readDerFile path =
    let
      val ins = BinIO.openIn path
      val content = BinIO.inputAll ins
      val () = BinIO.closeIn ins
    in
      Byte.bytesToString content
    end

  val fixturesDir = "test/fixtures/certs"

  fun readFixture name = readDerFile (fixturesDir ^ "/" ^ name)

  (* ---- signature algorithm constants (RFC 8446 §4.2.3) ---- *)
  val rsaPkcs1Sha256 = 0wx0804 : Word16.word
  val rsaPkcs1Sha384 = 0wx0805 : Word16.word
  val rsaPssSha256   = 0wx0809 : Word16.word

  (* A reasonable sigAlgs list for the tests: includes the PKCS#1 v1.5
     SHA-256 alg our fixtures use, plus a PSS variant. *)
  val sigAlgs = [rsaPkcs1Sha256, rsaPssSha256, rsaPkcs1Sha384]

  (* "now" inside the validity window of the leaf/intermediate/root
     fixtures (Jun 2026 - Sep 2028). Pick Jan 1 2027 00:00:00 UTC. *)
  val now = 1798761600        (* 2027-01-01T00:00:00Z *)

  (* ---- result pretty-printing (for failure diagnostics) ---- *)
  fun alertName a =
    case a of
      TlsAlert.CloseNotify              => "CloseNotify"
    | TlsAlert.UnexpectedMessage        => "UnexpectedMessage"
    | TlsAlert.BadRecordMac             => "BadRecordMac"
    | TlsAlert.RecordOverflow           => "RecordOverflow"
    | TlsAlert.HandshakeFailure         => "HandshakeFailure"
    | TlsAlert.BadCertificate           => "BadCertificate"
    | TlsAlert.UnsupportedCertificate   => "UnsupportedCertificate"
    | TlsAlert.CertificateRevoked       => "CertificateRevoked"
    | TlsAlert.CertificateExpired       => "CertificateExpired"
    | TlsAlert.CertificateUnknown       => "CertificateUnknown"
    | TlsAlert.IllegalParameter         => "IllegalParameter"
    | TlsAlert.UnknownCa                => "UnknownCa"
    | TlsAlert.AccessDenied             => "AccessDenied"
    | TlsAlert.DecodeError              => "DecodeError"
    | TlsAlert.DecryptError             => "DecryptError"
    | TlsAlert.ProtocolVersion          => "ProtocolVersion"
    | TlsAlert.InsufficientSecurity     => "InsufficientSecurity"
    | TlsAlert.InternalError            => "InternalError"
    | TlsAlert.UserCancelled            => "UserCancelled"
    | TlsAlert.MissingExtension         => "MissingExtension"
    | TlsAlert.UnsupportedExtension     => "UnsupportedExtension"
    | TlsAlert.UnrecognizedName         => "UnrecognizedName"
    | TlsAlert.BadCertificateStatus     => "BadCertificateStatus"
    | TlsAlert.UnknownPskIdentity       => "UnknownPskIdentity"
    | TlsAlert.CertificateRequired      => "CertificateRequired"
    | TlsAlert.NoApplicationProtocol    => "NoApplicationProtocol"
    | TlsAlert.Other w                  => "Other(0x" ^ Word8.toString w ^ ")"

  fun resultName r =
    case r of
      TlsCertVerify.Valid        => "Valid"
    | TlsCertVerify.Invalid a    => "Invalid " ^ alertName a

  (* Assert that [actual] equals [expected], printing both on failure. *)
  fun checkResult (name, expected, actual) =
    if expected = actual then check name true
    else
      let
        val () = print ("  FAIL - " ^ name ^ ": expected "
                        ^ resultName expected ^ " got "
                        ^ resultName actual ^ "\n")
      in
        check name false
      end

  (* The thunk-based check helpers let the test suite report a clean single
     failure for each assertion even when the implementation is still a
     `raise Fail "todo"` stub. Without them, an uncaught Fail would crash
     the whole test binary before later suites could run. *)

  (* Capture the outcome of a thunk: either SOME value or NONE with a
     printed diagnostic. *)
  fun try name thunk =
    let
      val r = ref NONE
      val v = (thunk () handle e =>
                 (r := SOME (exnMessage e);
                  TlsCertVerify.Invalid TlsAlert.InternalError))
    in
      case !r of
          SOME msg =>
            (print ("  FAIL - " ^ name ^ ": raised " ^ msg ^ "\n");
             NONE)
        | NONE => SOME v
    end

  fun tryBool name thunk =
    let
      val r = ref NONE
      val v = (thunk () handle e => (r := SOME (exnMessage e); false))
    in
      case !r of
          SOME msg =>
            (print ("  FAIL - " ^ name ^ ": raised " ^ msg ^ "\n");
             NONE)
        | NONE => SOME v
    end

  fun checkBoolThunk (name, expected, thunk) =
    case tryBool name thunk of
        NONE => check name false   (* already printed the raised line *)
      | SOME actual => check name (expected = actual)

  fun checkResultThunk (name, expected, thunk) =
    case try name thunk of
        NONE => check name false
      | SOME actual =>
          if expected = actual then check name true
          else
            let
              val () = print ("  FAIL - " ^ name ^ ": expected "
                              ^ resultName expected ^ " got "
                              ^ resultName actual ^ "\n")
            in
              check name false
            end

  (* ---- fixtures ---- *)
  val rootDer          = readFixture "root.der"
  val intermediateDer  = readFixture "intermediate.der"
  val leafDer          = readFixture "leaf.der"
  val expiredDer       = readFixture "expired-leaf.der"
  val wrongnameDer     = readFixture "wrongname-leaf.der"
  val untrustedRootDer = readFixture "untrusted-root.der"
  val untrustedLeafDer = readFixture "untrusted-leaf.der"
  val pathlenInterDer  = readFixture "pathlen-intermediate.der"
  val pathlenSubcaDer  = readFixture "pathlen-subca.der"
  val pathlenLeafDer   = readFixture "pathlen-leaf.der"
  val badsigInterDer   = readFixture "badsig-intermediate.der"

  (* The valid 3-cert chain, leaf-first. *)
  val validChain = [leafDer, intermediateDer, rootDer]

  (* The single trusted root for the valid-chain tests. *)
  val validTrust = [rootDer]

  fun run () =
    let
      val () = section "Certificate validation (A2)"

      (* ---- matchHostname unit tests (RFC 6125 wildcard rules) ---- *)
      val () = section "Certificate validation (A2) - matchHostname"

      (* Exact match. *)
      val () = checkBoolThunk ("exact match",
        true, fn () => TlsCertVerify.matchHostname {host = "www.example.com",
                                                    certName = "www.example.com"})

      (* Case-insensitive ASCII comparison. *)
      val () = checkBoolThunk ("case-insensitive match",
        true, fn () => TlsCertVerify.matchHostname {host = "WWW.EXAMPLE.com",
                                                    certName = "www.example.com"})

      (* Wildcard in leftmost label: `*.example.com` matches `x.example.com`. *)
      val () = checkBoolThunk ("wildcard matches single left label",
        true, fn () => TlsCertVerify.matchHostname {host = "x.example.com",
                                                    certName = "*.example.com"})

      (* Wildcard does NOT match the bare parent domain. *)
      val () = checkBoolThunk ("wildcard does not match parent",
        false, fn () => TlsCertVerify.matchHostname {host = "example.com",
                                                     certName = "*.example.com"})

      (* Wildcard does NOT match multi-label left. *)
      val () = checkBoolThunk ("wildcard does not match multi left labels",
        false, fn () => TlsCertVerify.matchHostname {host = "x.y.example.com",
                                                     certName = "*.example.com"})

      (* Wildcard only valid in the leftmost label. *)
      val () = checkBoolThunk ("non-leftmost wildcard is literal",
        false, fn () => TlsCertVerify.matchHostname {host = "a.b.example.com",
                                                     certName = "a.*.example.com"})

      (* Wildcard does not match empty left label. *)
      val () = checkBoolThunk ("wildcard requires a left label",
        false, fn () => TlsCertVerify.matchHostname {host = ".example.com",
                                                     certName = "*.example.com"})

      (* Mismatch on exact. *)
      val () = checkBoolThunk ("exact mismatch",
        false, fn () => TlsCertVerify.matchHostname {host = "www.other.com",
                                                     certName = "www.example.com"})

      (* ---- verifyChain fixture tests ---- *)
      val () = section "Certificate validation (A2) - verifyChain"

      (* 1. Valid 3-cert chain -> Valid. *)
      val () = checkResultThunk ("valid 3-cert chain",
        TlsCertVerify.Valid,
        fn () => TlsCertVerify.verifyChain {chain    = validChain,
                                            trust    = validTrust,
                                            hostname = "www.example.com",
                                            now      = now,
                                            sigAlgs  = sigAlgs})

      (* 1b. Valid chain, host matched via wildcard SAN (`*.example.com`). *)
      val () = checkResultThunk ("valid chain wildcard host",
        TlsCertVerify.Valid,
        fn () => TlsCertVerify.verifyChain {chain    = validChain,
                                            trust    = validTrust,
                                            hostname = "foo.example.com",
                                            now      = now,
                                            sigAlgs  = sigAlgs})

      (* 2. Expired leaf -> Invalid CertificateExpired. *)
      val () = checkResultThunk ("expired leaf",
        TlsCertVerify.Invalid TlsAlert.CertificateExpired,
        fn () => TlsCertVerify.verifyChain
          {chain    = [expiredDer, intermediateDer, rootDer],
           trust    = validTrust,
           hostname = "www.example.com",
           now      = now,
           sigAlgs  = sigAlgs})

      (* 3. Wrong hostname (SAN doesn't match) -> Invalid UnrecognizedName. *)
      val () = checkResultThunk ("wrong hostname",
        TlsCertVerify.Invalid TlsAlert.UnrecognizedName,
        fn () => TlsCertVerify.verifyChain {chain    = validChain,
                                            trust    = validTrust,
                                            hostname = "www.other.com",
                                            now      = now,
                                            sigAlgs  = sigAlgs})

      (* 4. Untrusted root (chain doesn't lead to a trust anchor). *)
      val () = checkResultThunk ("untrusted root",
        TlsCertVerify.Invalid TlsAlert.UnknownCa,
        fn () => TlsCertVerify.verifyChain
          {chain    = [untrustedLeafDer, untrustedRootDer],
           trust    = validTrust,
           hostname = "www.example.com",
           now      = now,
           sigAlgs  = sigAlgs})

      (* 5. pathLen violation: pathlen-intermediate (pathLen=0) signs another
            CA, which signs the leaf. The sub-CA link is the violation. *)
      val () = checkResultThunk ("pathLen violation",
        TlsCertVerify.Invalid TlsAlert.BadCertificate,
        fn () => TlsCertVerify.verifyChain
          {chain    = [pathlenLeafDer, pathlenSubcaDer, pathlenInterDer, rootDer],
           trust    = validTrust,
           hostname = "www.example.com",
           now      = now,
           sigAlgs  = sigAlgs})

      (* 6. Bad signature on intermediate (tampered DER). *)
      val () = checkResultThunk ("bad signature on intermediate",
        TlsCertVerify.Invalid TlsAlert.DecryptError,
        fn () => TlsCertVerify.verifyChain
          {chain    = [leafDer, badsigInterDer, rootDer],
           trust    = validTrust,
           hostname = "www.example.com",
           now      = now,
           sigAlgs  = sigAlgs})

      (* 7. Signature algorithm not in the acceptable list: the leaf is
            sha256WithRsaEncryption (0x0804); supply a list that omits it. *)
      val () = checkResultThunk ("sigAlg not in acceptable list",
        TlsCertVerify.Invalid TlsAlert.BadCertificate,
        fn () => TlsCertVerify.verifyChain
          {chain    = validChain,
           trust    = validTrust,
           hostname = "www.example.com",
           now      = now,
           sigAlgs  = [rsaPssSha256]})

      (* 8. Empty chain -> Invalid BadCertificate (no leaf to validate). *)
      val () = checkResultThunk ("empty chain",
        TlsCertVerify.Invalid TlsAlert.BadCertificate,
        fn () => TlsCertVerify.verifyChain {chain    = [],
                                            trust    = validTrust,
                                            hostname = "www.example.com",
                                            now      = now,
                                            sigAlgs  = sigAlgs})

      (* 9. Wrongname leaf in a chain -> Invalid UnrecognizedName
            (chain is structurally valid; only the name check fails). *)
      val () = checkResultThunk ("wrongname leaf chain",
        TlsCertVerify.Invalid TlsAlert.UnrecognizedName,
        fn () => TlsCertVerify.verifyChain
          {chain    = [wrongnameDer, intermediateDer, rootDer],
           trust    = validTrust,
           hostname = "www.example.com",
           now      = now,
           sigAlgs  = sigAlgs})
    in
      ()
    end
end
