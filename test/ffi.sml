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
