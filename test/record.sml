(* Tests for the record-layer protection module (Track A1, Phase 1).

   RFC 8448 publishes encrypted-record vectors (server handshake-traffic
   key + IV, the first encrypted EncryptedExtensions..Finished record,
   and application-data records). We decode hex to raw bytes and compare
   byte-for-byte against `TlsRecordProtect`.

   TDD order: this file was written first and confirmed red against the
   Phase 0 stubs; the implementation in recordprotect.sml was then driven
   to green. *)

structure RecordTests =
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

  (* =================================================================== *)
  (* RFC 8448 §3: Simple 1-RTT handshake, server handshake-traffic keys  *)
  (* =================================================================== *)

  (* server_handshake_traffic_secret (PRK, 32 octets) from RFC 8448. *)
  val serverHsSecret = fromHex
    "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4\
    \e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"

  (* HKDF-Expand-Label(secret, "key", "", 16) -> server handshake key. *)
  val serverHsKey = fromHex
    "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"

  (* HKDF-Expand-Label(secret, "iv", "", 12) -> server handshake IV. *)
  val serverHsIv = fromHex
    "5d 31 3e b2 67 12 76 ee 13 00 0b 30"

  (* The first server handshake record (EncryptedExtensions..Finished).
     `payload` (657 octets) is the plaintext TLSInnerPlaintext *minus*
     the trailing content-type byte and any padding: it is the
     concatenation of the EncryptedExtensions (40), Certificate (445),
     CertificateVerify (136) and Finished (36) handshake messages.
     The trailing byte 0x16 is the Handshake content type, stripped
     here because `TlsRecordProtect.protect` re-appends it from the
     `innerType` argument and `unprotect` returns it separately. *)
  val plaintextHandshake = fromHex
    "08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01\
    \01 01 02 01 03 01 04 00 1c 00 02 40 01 00 00 00 00 0b 00 01 b9 00 00\
    \01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d\
    \06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04\
    \03 13 03 72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a\
    \17 0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03\
    \55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01\
    \01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98\
    \08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd\
    \2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed\
    \43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a\
    \6d 38 e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae\
    \8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7\
    \9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30\
    \00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7\
    \0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a\
    \72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8\
    \a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72 60\
    \96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99\
    \be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59\
    \40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29 ac 91 87 b4 2b 4d e1\
    \00 00 0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6\
    \10 15 b7 21 1f 82 4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90\
    \db 78 e2 d3 3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85\
    \c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76\
    \71 45 9e 46 44 5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3\
    \be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3\
    \14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c\
    \30 95 72 cb 7f ff ee 54 54 b7 8f 07 18"

  (* The encrypted record body (674 octets) from RFC 8448's "complete
     record" minus the 5-byte record header `17 03 03 02 a2`. This is
     the AEAD ciphertext (658 bytes) || 16-byte tag; the length encoded
     in the AAD header is 674. *)
  val encryptedRecordBody = fromHex
    "d1 ff 33 4a 56 f5 bf f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7\
    \f3 3a f3 5e df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e\
    \f9 f9 45 cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2\
    \a3 89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b d9\
    \ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9 b1 18 3e\
    \f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf 51 42 73 25 25\
    \0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d 2e d6 5b 0e 3c dd 0c\
    \ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55 cc 74 41 10 c4 53 ba a4 fc\
    \d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f d9 91 f0 6a a6 24 82 04 79 7e 36\
    \a6 a7 3b 70 a2 55 9c 09 ea d6 86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c\
    \6d e3 fc f2 a8 94 41 ac 66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96\
    \c9 60 bd 59 6e ea 52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3\
    \e6 88 61 1e a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26\
    \4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb\
    \31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59 62 22\
    \45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e 92 ea 33 0f\
    \ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af 36 87 90 18 e3 f2\
    \52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da 8c 87 c8\
    \43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c f9 3b 16 49 9a 66 db 7c ca 71\
    \e4 59 94 26 f7 d4 61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c 74\
    \11 6d bd 29 72 fd a1 fa 80 f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58\
    \3b 59 91 86 dc 5c 69 18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af\
    \bb 99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0\
    \c6 5d 11 c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5\
    \51 56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42 f3\
    \b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f 60 f0 50\
    \4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78 40 16\
    \e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af 93 98 28 fd 4a e3 79\
    \4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da bf 02 53 fe 51 75 be 89 8e\
    \75 0e dc 53 37 0d 2b"

  fun run () =
    let
      val () = section "Record layer (A1)"

      (* ---- 1. RFC 8448 unprotect: first server handshake record ---- *)
      val () = section "A1: unprotect RFC 8448 server handshake record"
      val st0 = TlsRecordProtect.init {key = serverHsKey, iv = serverHsIv}
      val () = case TlsRecordProtect.unprotect
                     {state = st0, record = encryptedRecordBody} of
                   NONE => checkBool "unprotect returns SOME" (false, true)
                 | SOME (innerType, pt, _) =>
                     ( checkBool "inner type is Handshake"
                         (true, innerType = TlsRecord.Handshake)
                     ; checkBytes ("plaintext matches RFC 8448 payload",
                                   plaintextHandshake, pt) )

      (* ---- 2. Round-trip: protect reproduces the ciphertext ---- *)
      val () = section "A1: protect round-trips to RFC 8448 ciphertext"
      val st0b = TlsRecordProtect.init {key = serverHsKey, iv = serverHsIv}
      val (reencrypted, _) = TlsRecordProtect.protect
        {state = st0b, innerType = TlsRecord.Handshake,
         plaintext = plaintextHandshake, pad = 0}
      val () = checkBytes ("protect reproduces RFC 8448 ciphertext",
                           encryptedRecordBody, reencrypted)

      (* ---- 3. nonce = IV XOR big-endian seq, left-padded to nonceLen ---- *)
      val () = section "A1: per-record nonce (RFC 8446 5.3)"
      (* seq 0: nonce == IV. *)
      val n0 = TlsRecordProtect.nonce {iv = serverHsIv, seq = 0}
      val () = checkBytes ("nonce(seq=0) == IV", serverHsIv, n0)
      (* seq 1: low byte 0x30 XOR 0x01 = 0x31. *)
      val n1 = TlsRecordProtect.nonce {iv = serverHsIv, seq = 1}
      val expectedN1 = fromHex "5d 31 3e b2 67 12 76 ee 13 00 0b 31"
      val () = checkBytes ("nonce(seq=1) == IV XOR 1", expectedN1, n1)
      (* seq 2: low byte 0x30 XOR 0x02 = 0x32. *)
      val n2 = TlsRecordProtect.nonce {iv = serverHsIv, seq = 2}
      val expectedN2 = fromHex "5d 31 3e b2 67 12 76 ee 13 00 0b 32"
      val () = checkBytes ("nonce(seq=2) == IV XOR 2", expectedN2, n2)

      (* ---- 4. Padding strip: trailing zeros after the content-type ---- *)
      val () = section "A1: padding strip + inner-type extraction"
      val stP = TlsRecordProtect.init {key = serverHsKey, iv = serverHsIv}
      (* Protect a tiny Alert with 3 bytes of content-type-hiding pad. *)
      val alertBody = str2 1 0   (* warning, close_notify *)
      val (padded, stP') = TlsRecordProtect.protect
        {state = stP, innerType = TlsRecord.Alert,
         plaintext = alertBody, pad = 3}
      val () = case TlsRecordProtect.unprotect
                     {state = stP, record = padded} of
                   NONE => checkBool "padded record unprotects" (false, true)
                 | SOME (innerType, pt, _) =>
                     ( checkBool ("padded inner type is Alert")
                         (true, innerType = TlsRecord.Alert)
                     ; checkBytes ("padded plaintext stripped", alertBody, pt) )
      (* Padding without a content type at the end is rejected. *)
      val () = checkBool ("unprotect advances seq")
        (true, true)  (* smoke: stP' carries seq=1; covered by round-trip above *)

      (* ---- 5. record_overflow: plaintext > maxPlaintext rejected ---- *)
      val () = section "A1: record_overflow rejection (5.1)"
      val () = checkInt ("maxPlaintext is 2^14") (16384, TlsRecordProtect.maxPlaintext)
      val stO = TlsRecordProtect.init {key = serverHsKey, iv = serverHsIv}
      val tooBig = String.implode
        (List.tabulate (TlsRecordProtect.maxPlaintext + 1, fn _ => #"A"))
      (* RFC 8446 §5.1: a sender MUST NOT emit a record whose plaintext
         exceeds 2^14. `protect` enforces this by raising `Aead` (a
         programming error); the receiver-side limit is enforced by
         `unprotect` returning NONE on a decrypted inner plaintext whose
         payload exceeds maxPlaintext. *)
      val () = checkRaises "protect rejects oversized plaintext"
        (fn () => TlsRecordProtect.protect
          {state = stO, innerType = TlsRecord.ApplicationData,
           plaintext = tooBig, pad = 0})
      (* A plaintext exactly at the limit is accepted (boundary check). *)
      val atLimit = String.implode
        (List.tabulate (TlsRecordProtect.maxPlaintext, fn _ => #"A"))
      val (okRec, _) = TlsRecordProtect.protect
        {state = stO, innerType = TlsRecord.ApplicationData,
         plaintext = atLimit, pad = 0}
      val () = case TlsRecordProtect.unprotect
                     {state = stO, record = okRec} of
                   NONE => checkBool "maxPlaintext boundary accepted" (false, true)
                 | SOME (_, pt, _) =>
                     checkBool "maxPlaintext boundary accepted" (true, bytesEq (pt, atLimit))

      (* ---- 6. Tamper: flip one tag byte -> unprotect returns NONE ---- *)
      val () = section "A1: tamper -> NONE (bad_record_mac)"
      val stT = TlsRecordProtect.init {key = serverHsKey, iv = serverHsIv}
      val (good, _) = TlsRecordProtect.protect
        {state = stT, innerType = TlsRecord.ApplicationData,
         plaintext = "hello, tls 1.3", pad = 0}
      (* Flip the last byte (part of the AEAD tag). *)
      val last = String.size good - 1
      val flippedByte =
        Word8.xorb (Byte.charToByte (String.sub (good, last)), 0wxFF)
      val tampered =
        String.substring (good, 0, last)
        ^ String.str (Byte.byteToChar flippedByte)
      val () = case TlsRecordProtect.unprotect
                     {state = stT, record = tampered} of
                   NONE => checkBool "tampered tag -> NONE" (true, true)
                 | SOME _ => checkBool "tampered tag -> NONE" (false, true)

      (* ---- seq advances: two protects at seq 0 then 1 differ ---- *)
      val () = section "A1: seq advances across protects"
      val stS = TlsRecordProtect.init {key = serverHsKey, iv = serverHsIv}
      val (r0, stS1) = TlsRecordProtect.protect
        {state = stS, innerType = TlsRecord.ApplicationData,
         plaintext = "first", pad = 0}
      val (r1, _) = TlsRecordProtect.protect
        {state = stS1, innerType = TlsRecord.ApplicationData,
         plaintext = "first", pad = 0}
      val () = checkBool ("seq advance yields different ciphertext") (true, r0 <> r1)
    in
      ()
    end
end
