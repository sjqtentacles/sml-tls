(* ffi.sml

   Cross-implementation tests for the constant-time crypto FFI shim
   (lib/.../sml-crypto-ffi). Every assertion checks that the libsodium
   shim (CryptoFfi) produces BYTE-IDENTICAL output to the pure-SML oracle
   (X25519 / ChaCha20Poly1305) on the published RFC test vectors and on
   the existing handshake material, so the shim is a verified drop-in.

   These tests run under both MLton (_import) and Poly/ML (Foreign) via the
   per-compiler implementation files selected by the FFI build targets. *)

structure FfiTests =
struct
  open Harness

  fun nib c =
    if c >= #"0" andalso c <= #"9" then Char.ord c - 48
    else if c >= #"a" andalso c <= #"f" then Char.ord c - 87
    else if c >= #"A" andalso c <= #"F" then Char.ord c - 55
    else ~1

  fun fromHex s =
    let
      fun isSpace c = c = #" " orelse c = #"\n" orelse c = #"\t" orelse c = #"\r"
      val cleaned = String.implode (List.filter (not o isSpace) (String.explode s))
      val n = String.size cleaned
      fun loop (i, acc) =
        if i >= n then String.implode (List.rev acc)
        else
          let val hi = nib (String.sub (cleaned, i))
              val lo = nib (String.sub (cleaned, i + 1))
          in if hi < 0 orelse lo < 0 then raise Fail "bad hex"
             else loop (i + 2, Char.chr (hi * 16 + lo) :: acc) end
    in loop (0, []) end

  fun toHex s =
    let fun one c =
      let val v = Char.ord c
          fun d n = if n < 10 then Char.chr (48 + n) else Char.chr (87 + n)
      in String.implode [d (v div 16), d (v mod 16)] end
    in String.concat (List.map one (String.explode s)) end

  fun checkBytes (name, expected, actual) =
    if String.size expected = String.size actual andalso expected = actual
    then check name true
    else (print ("  FAIL - " ^ name ^ ": " ^ toHex expected ^ " <> "
                 ^ toHex actual ^ "\n"); check name false)

  (* Read a binary fixture file (relative to the repo root, where the test
     binary runs) as a raw byte string. Works under MLton and Poly/ML. *)
  fun readBin path =
    let
      val ins = BinIO.openIn path
      val content = BinIO.inputAll ins
      val () = BinIO.closeIn ins
    in
      Byte.bytesToString content
    end

  fun run () =
    let
      val () = CryptoFfi.init ()

      (* =============================================================== *)
      val () = section "FFI X25519: RFC 7748 vectors (shim == oracle)"

      (* RFC 7748 section 5.2, first test vector. *)
      val k1 = fromHex
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
      val u1 = fromHex
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
      val expect1 = fromHex
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
      val () = checkBytes ("RFC 7748 vec1: oracle matches expected",
                           expect1, X25519.dh k1 u1)
      val () = checkBytes ("RFC 7748 vec1: FFI matches expected",
                           expect1, CryptoFfi.dh k1 u1)
      val () = checkBytes ("RFC 7748 vec1: FFI byte-identical to oracle",
                           X25519.dh k1 u1, CryptoFfi.dh k1 u1)

      (* RFC 7748 section 5.2, second test vector. *)
      val k2 = fromHex
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
      val u2 = fromHex
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
      val expect2 = fromHex
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
      val () = checkBytes ("RFC 7748 vec2: FFI byte-identical to oracle",
                           X25519.dh k2 u2, CryptoFfi.dh k2 u2)
      val () = checkBytes ("RFC 7748 vec2: FFI matches expected",
                           expect2, CryptoFfi.dh k2 u2)

      (* base() agreement on an arbitrary scalar, plus a full ECDHE
         agreement: client/server derive the same shared secret. *)
      val () = section "FFI X25519: base + ECDHE agreement (shim == oracle)"
      val skA = String.implode (List.tabulate (32, fn i => Char.chr ((i*7+1) mod 256)))
      val skB = String.implode (List.tabulate (32, fn i => Char.chr ((i*5+9) mod 256)))
      val () = checkBytes ("base(skA): FFI == oracle",
                           X25519.base skA, CryptoFfi.base skA)
      val pkA_o = X25519.base skA  and pkB_o = X25519.base skB
      val () = checkBytes ("ECDHE shared (oracle dh): A.B == B.A",
                           X25519.dh skA pkB_o, X25519.dh skB pkA_o)
      val () = checkBytes ("ECDHE shared: FFI(A.pkB) == oracle(A.pkB)",
                           X25519.dh skA pkB_o, CryptoFfi.dh skA pkB_o)
      val () = checkBytes ("ECDHE shared: FFI(A.pkB) == FFI(B.pkA)",
                           CryptoFfi.dh skA pkB_o, CryptoFfi.dh skB pkA_o)

      (* =============================================================== *)
      val () = section "FFI ChaCha20-Poly1305: RFC 8439 vector (shim == oracle)"

      (* RFC 8439 section 2.8.2. *)
      val key = fromHex
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
      val nonce = fromHex "070000004041424344454647"
      val aad = fromHex "50515253c0c1c2c3c4c5c6c7"
      val pt = fromHex
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
        \73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
        \6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
        \637265656e20776f756c642062652069742e"
      val expectCt = fromHex
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
        \3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
        \92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
        \3ff4def08e4b7a9de576d26586cec64b6116"
      val expectTag = fromHex "1ae10b594f09e26a7e902ecbd0600691"
      val expectSealed = expectCt ^ expectTag

      val oracleSealed = ChaCha20Poly1305.seal key nonce aad pt
      val () = checkBytes ("RFC 8439: oracle seal matches expected",
                           expectSealed, oracleSealed)
      val ffiSealed = CryptoFfi.ChaCha20Poly1305.seal key nonce aad pt
      val () = checkBytes ("RFC 8439: FFI seal matches expected",
                           expectSealed, ffiSealed)
      val () = checkBytes ("RFC 8439: FFI seal byte-identical to oracle",
                           oracleSealed, ffiSealed)

      (* open' round-trips and cross-decrypts. *)
      val () = section "FFI ChaCha20-Poly1305: open' cross-decrypts"
      val () = case CryptoFfi.ChaCha20Poly1305.open' key nonce aad oracleSealed of
                   SOME p => checkBytes ("FFI open'(oracle seal) == plaintext", pt, p)
                 | NONE => check "FFI open'(oracle seal) authenticates" false
      val () = case ChaCha20Poly1305.open' key nonce aad ffiSealed of
                   SOME p => checkBytes ("oracle open'(FFI seal) == plaintext", pt, p)
                 | NONE => check "oracle open'(FFI seal) authenticates" false

      (* Tamper: a flipped tag byte must fail to authenticate. *)
      val tampered =
        let val n = String.size ffiSealed
            val last = Char.ord (String.sub (ffiSealed, n - 1))
        in String.substring (ffiSealed, 0, n - 1)
           ^ String.str (Char.chr (last mod 256 + (if last = 0 then 1 else ~1)))
        end
      val () = check "FFI open' rejects a tampered tag"
        (CryptoFfi.ChaCha20Poly1305.open' key nonce aad tampered = NONE)

      (* Empty-plaintext and empty-aad edge cases agree. *)
      val () = section "FFI ChaCha20-Poly1305: empty edge cases (shim == oracle)"
      val () = checkBytes ("seal empty pt: FFI == oracle",
                 ChaCha20Poly1305.seal key nonce aad "",
                 CryptoFfi.ChaCha20Poly1305.seal key nonce aad "")
      val () = checkBytes ("seal empty aad: FFI == oracle",
                 ChaCha20Poly1305.seal key nonce "" pt,
                 CryptoFfi.ChaCha20Poly1305.seal key nonce "" pt)

      (* =============================================================== *)
      val () = section "FFI AES-128-GCM: NIST vector (shim == oracle)"

      (* NIST GCM test vector (gcmEncryptExtIV128, 96-bit IV, with AAD).
         Source: NIST CAVP gcmEncryptExtIV128.rsp, Keylen=128 Taglen=128. *)
      val aes128Key = fromHex "feffe9928665731c6d6a8f9467308308"
      val aes128Iv  = fromHex "cafebabefacedbaddecaf888"
      val aes128Aad = fromHex "feedfacedeadbeeffeedfacedeadbeefabaddad2"
      val aes128Pt  = fromHex
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
        \1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
      val aes128Exp = fromHex
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
        \21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
        \5bc94fbc3221a5db94fae95ae7121a47"
      val aes128OracleSealed = AesGcm.seal aes128Key aes128Iv aes128Aad aes128Pt
      val () = checkBytes ("AES-128-GCM: oracle seal matches NIST",
                           aes128Exp, aes128OracleSealed)
      val aes128FfiSealed = CryptoFfi.AesGcm.seal aes128Key aes128Iv aes128Aad aes128Pt
      val () = checkBytes ("AES-128-GCM: FFI seal matches NIST",
                           aes128Exp, aes128FfiSealed)
      val () = checkBytes ("AES-128-GCM: FFI seal byte-identical to oracle",
                           aes128OracleSealed, aes128FfiSealed)
      val () = case CryptoFfi.AesGcm.open' aes128Key aes128Iv aes128Aad aes128OracleSealed of
                   SOME p => checkBytes ("AES-128-GCM: FFI open'(oracle seal) == pt", aes128Pt, p)
                 | NONE => check "AES-128-GCM: FFI open'(oracle seal) authenticates" false
      val () = case AesGcm.open' aes128Key aes128Iv aes128Aad aes128FfiSealed of
                   SOME p => checkBytes ("AES-128-GCM: oracle open'(FFI seal) == pt", aes128Pt, p)
                 | NONE => check "AES-128-GCM: oracle open'(FFI seal) authenticates" false

      (* =============================================================== *)
      val () = section "FFI AES-256-GCM: NIST vector (shim == oracle)"

      (* NIST GCM test vector (gcmEncryptExtIV256, 96-bit IV, with AAD).
         Source: NIST CAVP gcmEncryptExtIV256.rsp, Keylen=256 Taglen=128. *)
      val aes256Key = fromHex
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
      val aes256Iv  = fromHex "cafebabefacedbaddecaf888"
      val aes256Aad = fromHex "feedfacedeadbeeffeedfacedeadbeefabaddad2"
      val aes256Pt  = fromHex
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
        \1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
      val aes256Exp = fromHex
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
        \8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
        \76fc6ece0f4e1768cddf8853bb2d551b"
      val aes256OracleSealed = AesGcm.seal aes256Key aes256Iv aes256Aad aes256Pt
      val () = checkBytes ("AES-256-GCM: oracle seal matches NIST",
                           aes256Exp, aes256OracleSealed)
      val aes256FfiSealed = CryptoFfi.AesGcm.seal aes256Key aes256Iv aes256Aad aes256Pt
      val () = checkBytes ("AES-256-GCM: FFI seal matches NIST",
                           aes256Exp, aes256FfiSealed)
      val () = checkBytes ("AES-256-GCM: FFI seal byte-identical to oracle",
                           aes256OracleSealed, aes256FfiSealed)
      val () = case CryptoFfi.AesGcm.open' aes256Key aes256Iv aes256Aad aes256FfiSealed of
                   SOME p => checkBytes ("AES-256-GCM: FFI open'(FFI seal) == pt", aes256Pt, p)
                 | NONE => check "AES-256-GCM: FFI open'(FFI seal) authenticates" false
      val () = case AesGcm.open' aes256Key aes256Iv aes256Aad aes256FfiSealed of
                   SOME p => checkBytes ("AES-256-GCM: oracle open'(FFI seal) == pt", aes256Pt, p)
                 | NONE => check "AES-256-GCM: oracle open'(FFI seal) authenticates" false

      (* Tamper + empty edge cases. *)
      val () = section "FFI AES-GCM: tamper + empty edge cases"
      val aesTampered =
        let val n = String.size aes128FfiSealed
            val last = Char.ord (String.sub (aes128FfiSealed, n - 1))
        in String.substring (aes128FfiSealed, 0, n - 1)
           ^ String.str (Char.chr (last mod 256 + (if last = 0 then 1 else ~1)))
        end
      val () = check "AES-128-GCM: FFI open' rejects a tampered tag"
        (CryptoFfi.AesGcm.open' aes128Key aes128Iv aes128Aad aesTampered = NONE)
      val () = checkBytes ("AES-128-GCM: seal empty pt: FFI == oracle",
                 AesGcm.seal aes128Key aes128Iv aes128Aad "",
                 CryptoFfi.AesGcm.seal aes128Key aes128Iv aes128Aad "")
      val () = checkBytes ("AES-128-GCM: seal empty aad: FFI == oracle",
                 AesGcm.seal aes128Key aes128Iv "" aes128Pt,
                 CryptoFfi.AesGcm.seal aes128Key aes128Iv "" aes128Pt)

      (* =============================================================== *)
      val () = section "FFI RSA-PSS-SHA256: cross-verify (shim <-> oracle)"

      (* Reuse the committed RSA key/cert fixtures (test/fixtures/certs):
         cv-key.pkcs8.der is the private key, its public half is used to
         verify. No new key material is invented. *)
      val rsaPriv  = Rsa.decodePkcs8Der (readBin "test/fixtures/certs/cv-key.pkcs8.der")
      val rsaPub   = Rsa.pubOf rsaPriv
      val rsaSpki  = Rsa.encodeSpkiDer rsaPub
      val rsaPkcs8 = Rsa.encodePkcs8Der rsaPriv

      val rsaMsg = "TLS 1.3 CertificateVerify transcript (FFI cross-check)"

      (* TLS case: SHA-256, saltLen 32. Oracle-signed (fixed zero salt, pure
         SML) must verify under the FFI/OpenSSL verifier. We use the pure
         oracles explicitly (Rsa.signPssPure / verifyPssPure) so this remains
         a genuine pure-vs-FFI cross-check even in the FFI build, where
         Rsa.signPss / verifyPss are themselves routed through OpenSSL. *)
      val cvSalt   = String.implode (List.tabulate (32, fn _ => Char.chr 0))
      val oracleSig = Rsa.signPssPure {priv = rsaPriv, hash = Rsa.SHA256,
                                       salt = cvSalt, msg = rsaMsg}
      val () = check "RSA-PSS-256 saltLen32: FFI verifies oracle signature"
        (CryptoFfi.RsaPss.verify {spkiDer = rsaSpki, hashId = 1, saltLen = 32,
                                  msg = rsaMsg, sgn = oracleSig})

      (* FFI-signed (random salt) must verify under the pure oracle. *)
      val ffiSig = CryptoFfi.RsaPss.sign {pkcs8Der = rsaPkcs8, hashId = 1,
                                          saltLen = 32, msg = rsaMsg}
      val () = check "RSA-PSS-256 saltLen32: oracle verifies FFI signature"
        (Rsa.verifyPssPure {pub = rsaPub, hash = Rsa.SHA256, saltLen = 32,
                            msg = rsaMsg, sgn = ffiSig})
      val () = check "RSA-PSS-256 saltLen32: FFI verifies FFI signature"
        (CryptoFfi.RsaPss.verify {spkiDer = rsaSpki, hashId = 1, saltLen = 32,
                                  msg = rsaMsg, sgn = ffiSig})

      (* Wrong message must NOT verify (either direction). *)
      val () = check "RSA-PSS-256: FFI rejects wrong message"
        (not (CryptoFfi.RsaPss.verify {spkiDer = rsaSpki, hashId = 1, saltLen = 32,
                                       msg = rsaMsg ^ "x", sgn = oracleSig}))
      val () = check "RSA-PSS-256: oracle rejects wrong message"
        (not (Rsa.verifyPssPure {pub = rsaPub, hash = Rsa.SHA256, saltLen = 32,
                                 msg = rsaMsg ^ "x", sgn = ffiSig}))

      (* Tampered signature must NOT verify under the FFI verifier. *)
      val rsaSigBad =
        let val n = String.size oracleSig
            val last = Char.ord (String.sub (oracleSig, n - 1))
        in String.substring (oracleSig, 0, n - 1)
           ^ String.str (Char.chr (last mod 256 + (if last = 0 then 1 else ~1)))
        end
      val () = check "RSA-PSS-256: FFI rejects a tampered signature"
        (not (CryptoFfi.RsaPss.verify {spkiDer = rsaSpki, hashId = 1, saltLen = 32,
                                       msg = rsaMsg, sgn = rsaSigBad}))

      (* X.509-style case: SHA-256, a different saltLen (20). Cross-verify. *)
      val () = section "FFI RSA-PSS-SHA256: X.509-style saltLen (cross-verify)"
      val x509Sig = CryptoFfi.RsaPss.sign {pkcs8Der = rsaPkcs8, hashId = 1,
                                           saltLen = 20, msg = rsaMsg}
      val () = check "RSA-PSS-256 saltLen20: oracle verifies FFI signature"
        (Rsa.verifyPssPure {pub = rsaPub, hash = Rsa.SHA256, saltLen = 20,
                            msg = rsaMsg, sgn = x509Sig})
      val x509OracleSig = Rsa.signPssPure {priv = rsaPriv, hash = Rsa.SHA256,
                                           salt = String.implode (List.tabulate (20, fn _ => Char.chr 0)),
                                           msg = rsaMsg}
      val () = check "RSA-PSS-256 saltLen20: FFI verifies oracle signature"
        (CryptoFfi.RsaPss.verify {spkiDer = rsaSpki, hashId = 1, saltLen = 20,
                                  msg = rsaMsg, sgn = x509OracleSig})

      (* =============================================================== *)
      val () = section "FFI memzero (Track 1b primitive)"
      val buf = Word8Array.tabulate (16, fn i => Word8.fromInt (i + 1))
      val () = check "buffer starts non-zero"
        (Word8Array.foldl (fn (b, acc) => acc orelse b <> 0w0) false buf)
      val () = CryptoFfi.memzero buf
      val () = check "memzero wipes buffer to all zeros"
        (Word8Array.foldl (fn (b, acc) => acc andalso b = 0w0) true buf)
    in
      ()
    end
end
