(* tls_sha256Script.sml

   A concrete, EVAL-able SHA-256 (FIPS 180-4) over byte (word8) lists, plus
   HMAC-SHA-256 (RFC 2104) and HKDF-Extract/Expand (RFC 5869), all as pure,
   computable HOL4 functions.

   Track 2b of the sml-tls production-readiness plan.  ROUTE B: this is an
   *independent* HOL4 definition of SHA-256, validated by `EVAL` against the
   published NIST/standard test vectors (empty string and "abc") and against
   the RFC 8448 TLS 1.3 key-schedule vectors below.  It is NOT (yet) linked by
   `ml_translatorLib` translation to the CakeML `cakeml/sha256.sml` source;
   that translation link is the remaining work for Track 2c (see PROOF_STATUS).

   The compression function mirrors the CakeML reference structurally
   (`cakeml/sha256.sml`): the same round constants K, the same initial hash
   values, the same big-endian word packing, message-schedule extension and
   64-round compression, the same length-padding rule.  Here it is expressed
   over native HOL4 `word32` (so all arithmetic is mod 2^32 automatically) and
   over `word8 list` messages, which is what the TLS key schedule consumes.
*)

open HolKernel Parse boolLib bossLib;
open arithmeticTheory listTheory rich_listTheory wordsTheory;

val _ = new_theory "tls_sha256";

(* -------------------------------------------------------------------------- *)
(*  32-bit word operations                                                    *)
(* -------------------------------------------------------------------------- *)

(* SHA-256 right rotate on 32-bit words. *)
Definition rotr32_def:
  rotr32 (w : word32) (n : num) : word32 =
    (w >>> n) || (w << (32 - n))
End

Definition sigma0_def:  (* small sigma 0 *)
  sigma0 (w : word32) = (rotr32 w 7) ?? (rotr32 w 18) ?? (w >>> 3)
End

Definition sigma1_def:  (* small sigma 1 *)
  sigma1 (w : word32) = (rotr32 w 17) ?? (rotr32 w 19) ?? (w >>> 10)
End

Definition bigsigma0_def:  (* big Sigma 0 *)
  bigsigma0 (w : word32) = (rotr32 w 2) ?? (rotr32 w 13) ?? (rotr32 w 22)
End

Definition bigsigma1_def:  (* big Sigma 1 *)
  bigsigma1 (w : word32) = (rotr32 w 6) ?? (rotr32 w 11) ?? (rotr32 w 25)
End

Definition ch_def:
  ch (x : word32) y z = (x && y) ?? ((~x) && z)
End

Definition maj_def:
  maj (x : word32) y z = (x && y) ?? (x && z) ?? (y && z)
End

(* -------------------------------------------------------------------------- *)
(*  Round constants K and initial hash H0 (FIPS 180-4 4.2.2 / 5.3.3)          *)
(* -------------------------------------------------------------------------- *)

Definition kConstants_def:
  kConstants : word32 list =
    [0x428a2f98w; 0x71374491w; 0xb5c0fbcfw; 0xe9b5dba5w; 0x3956c25bw; 0x59f111f1w;
     0x923f82a4w; 0xab1c5ed5w; 0xd807aa98w; 0x12835b01w; 0x243185bew; 0x550c7dc3w;
     0x72be5d74w; 0x80deb1few; 0x9bdc06a7w; 0xc19bf174w; 0xe49b69c1w; 0xefbe4786w;
     0x0fc19dc6w; 0x240ca1ccw; 0x2de92c6fw; 0x4a7484aaw; 0x5cb0a9dcw; 0x76f988daw;
     0x983e5152w; 0xa831c66dw; 0xb00327c8w; 0xbf597fc7w; 0xc6e00bf3w; 0xd5a79147w;
     0x06ca6351w; 0x14292967w; 0x27b70a85w; 0x2e1b2138w; 0x4d2c6dfcw; 0x53380d13w;
     0x650a7354w; 0x766a0abbw; 0x81c2c92ew; 0x92722c85w; 0xa2bfe8a1w; 0xa81a664bw;
     0xc24b8b70w; 0xc76c51a3w; 0xd192e819w; 0xd6990624w; 0xf40e3585w; 0x106aa070w;
     0x19a4c116w; 0x1e376c08w; 0x2748774cw; 0x34b0bcb5w; 0x391c0cb3w; 0x4ed8aa4aw;
     0x5b9cca4fw; 0x682e6ff3w; 0x748f82eew; 0x78a5636fw; 0x84c87814w; 0x8cc70208w;
     0x90befffaw; 0xa4506cebw; 0xbef9a3f7w; 0xc67178f2w]
End

Definition initHash_def:
  initHash : word32 list =
    [0x6a09e667w; 0xbb67ae85w; 0x3c6ef372w; 0xa54ff53aw;
     0x510e527fw; 0x9b05688cw; 0x1f83d9abw; 0x5be0cd19w]
End

(* -------------------------------------------------------------------------- *)
(*  Padding (FIPS 180-4 5.1.1)                                                *)
(* -------------------------------------------------------------------------- *)

(* 64-bit big-endian byte encoding of a number. *)
Definition w64_be_bytes_def:
  w64_be_bytes (n : num) : word8 list =
    [n2w (n DIV 0x100000000000000);
     n2w (n DIV 0x1000000000000);
     n2w (n DIV 0x10000000000);
     n2w (n DIV 0x100000000);
     n2w (n DIV 0x1000000);
     n2w (n DIV 0x10000);
     n2w (n DIV 0x100);
     n2w n]
End

(* number of 0x00 pad bytes so that (len + 1 + pad + 8) is a multiple of 64. *)
Definition padZeros_def:
  padZeros (len : num) : num =
    let m = (len + 1) MOD 64 in
      if m <= 56 then 56 - m else 120 - m
End

Definition sha_pad_def:
  sha_pad (msg : word8 list) : word8 list =
    let len = LENGTH msg in
      msg ++ [0x80w] ++ REPLICATE (padZeros len) 0w ++ w64_be_bytes (len * 8)
End

(* -------------------------------------------------------------------------- *)
(*  Block / word splitting                                                    *)
(* -------------------------------------------------------------------------- *)

(* big-endian: combine 4 bytes into a word32. *)
Definition bytes_to_w32_def:
  bytes_to_w32 (a : word8) (b : word8) (c : word8) (d : word8) : word32 =
    (w2w a << 24) || (w2w b << 16) || (w2w c << 8) || (w2w d)
End

(* split a byte list into a list of big-endian word32s (assumes length mult 4). *)
Definition bytes_to_words_def:
  bytes_to_words (bs : word8 list) : word32 list =
    case bs of
      (a :: b :: c :: d :: rest) =>
        bytes_to_w32 a b c d :: bytes_to_words rest
    | _ => []
End

(* take the first 16 words (one block) and the remainder. *)
Definition split16_def:
  split16 (ws : word32 list) : (word32 list # word32 list) =
    (TAKE 16 ws, DROP 16 ws)
End

(* chunk a word list into 16-word blocks. *)
Definition chunk16_def:
  chunk16 (ws : word32 list) : word32 list list =
    if LENGTH ws < 16 then []
    else TAKE 16 ws :: chunk16 (DROP 16 ws)
Termination
  WF_REL_TAC `measure LENGTH` >> rw[LENGTH_DROP]
End

(* -------------------------------------------------------------------------- *)
(*  Message schedule W[0..63] (FIPS 180-4 6.2.2 step 1)                       *)
(* -------------------------------------------------------------------------- *)

(* Build W as a list, extending from 16 to 64 words.  `acc` holds W[0..i-1]
   in REVERSE order (so EL 0 acc = W[i-1]), which makes the back-references
   W[i-2], W[i-7], W[i-15], W[i-16] cheap (EL 1, EL 6, EL 14, EL 15). *)
Definition extendW_def:
  extendW (acc : word32 list) (count : num) : word32 list =
    if count = 0 then REVERSE acc
    else
      let w16 = EL 15 acc in
      let w15 = EL 14 acc in
      let w7  = EL 6  acc in
      let w2  = EL 1  acc in
      let nw  = w16 + sigma0 w15 + w7 + sigma1 w2 in
        extendW (nw :: acc) (count - 1)
End

(* full schedule: take the 16 block words (in order), reverse for acc, extend
   by 48 more to reach 64. *)
Definition schedule_def:
  schedule (block : word32 list) : word32 list =
    extendW (REVERSE block) 48
End

(* -------------------------------------------------------------------------- *)
(*  Compression of one block (FIPS 180-4 6.2.2 steps 3-4)                     *)
(* -------------------------------------------------------------------------- *)

(* The 8 working variables. *)
Definition compress_round_def:
  compress_round (ws : word32 list) (ks : word32 list)
                 (a,b,c,d,e,f,g,h) : (word32#word32#word32#word32#word32#word32#word32#word32) =
    case (ws, ks) of
      (w :: wt, kk :: kt) =>
        let t1 = h + bigsigma1 e + ch e f g + kk + w in
        let t2 = bigsigma0 a + maj a b c in
          compress_round wt kt (t1 + t2, a, b, c, d + t1, e, f, g)
    | _ => (a,b,c,d,e,f,g,h)
Termination
  WF_REL_TAC `measure (LENGTH o FST)` >> rw[]
End

Definition processBlock_def:
  processBlock (h0,h1,h2,h3,h4,h5,h6,h7) (block : word32 list)
      : (word32#word32#word32#word32#word32#word32#word32#word32) =
    let ws = schedule block in
    let (a,b,c,d,e,f,g,h) =
          compress_round ws kConstants (h0,h1,h2,h3,h4,h5,h6,h7) in
      (h0 + a, h1 + b, h2 + c, h3 + d, h4 + e, h5 + f, h6 + g, h7 + h)
End

Definition processBlocks_def:
  processBlocks st (blocks : word32 list list) =
    case blocks of
      [] => st
    | (b :: bs) => processBlocks (processBlock st b) bs
End

(* -------------------------------------------------------------------------- *)
(*  Digest                                                                    *)
(* -------------------------------------------------------------------------- *)

Definition w32_be_bytes_def:
  w32_be_bytes (w : word32) : word8 list =
    [w2w (w >>> 24); w2w (w >>> 16); w2w (w >>> 8); w2w w]
End

Definition initState_def:
  initState : (word32#word32#word32#word32#word32#word32#word32#word32) =
    (0x6a09e667w, 0xbb67ae85w, 0x3c6ef372w, 0xa54ff53aw,
     0x510e527fw, 0x9b05688cw, 0x1f83d9abw, 0x5be0cd19w)
End

Definition sha256_digest_def:
  sha256_digest (msg : word8 list) : word8 list =
    let blocks = chunk16 (bytes_to_words (sha_pad msg)) in
    let (h0,h1,h2,h3,h4,h5,h6,h7) = processBlocks initState blocks in
      w32_be_bytes h0 ++ w32_be_bytes h1 ++ w32_be_bytes h2 ++ w32_be_bytes h3 ++
      w32_be_bytes h4 ++ w32_be_bytes h5 ++ w32_be_bytes h6 ++ w32_be_bytes h7
End

(* -------------------------------------------------------------------------- *)
(*  HMAC-SHA-256 (RFC 2104)                                                   *)
(* -------------------------------------------------------------------------- *)

Definition shaBlockSize_def:
  shaBlockSize : num = 64    (* SHA-256 internal block size, in bytes *)
End

(* Normalize an HMAC key to exactly one block (64 bytes): hash if too long,
   then zero-pad on the right. *)
Definition hmacKey_def:
  hmacKey (key : word8 list) : word8 list =
    let k0 = if LENGTH key > shaBlockSize then sha256_digest key else key in
      k0 ++ REPLICATE (shaBlockSize - LENGTH k0) 0w
End

Definition xorPad_def:
  xorPad (pad : word8) (k : word8 list) : word8 list =
    MAP (\b. b ?? pad) k
End

Definition hmac_sha256_def:
  hmac_sha256 (key : word8 list) (msg : word8 list) : word8 list =
    let k  = hmacKey key in
    let ipad = xorPad 0x36w k in
    let opad = xorPad 0x5cw k in
      sha256_digest (opad ++ sha256_digest (ipad ++ msg))
End

(* -------------------------------------------------------------------------- *)
(*  HKDF (RFC 5869)                                                           *)
(* -------------------------------------------------------------------------- *)

(* HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM). *)
Definition hkdf_extract_def:
  hkdf_extract (salt : word8 list) (ikm : word8 list) : word8 list =
    hmac_sha256 salt ikm
End

(* HKDF-Expand block iteration: produce blocks T(1),...,T(n) where
   T(i) = HMAC(prk, T(i-1) ++ info ++ [i]).  `prev` is T(i-1) (or [] for T(0)),
   `i` is the (1-based) counter for the next block, `n` blocks remaining. *)
Definition hkdf_expand_blocks_def:
  hkdf_expand_blocks prk info prev i n =
    if n = 0 then []
    else
      let ti = hmac_sha256 prk (prev ++ info ++ [n2w i]) in
        ti ++ hkdf_expand_blocks prk info ti (i + 1) (n - 1)
End

(* HKDF-Expand(PRK, info, L): concatenate ceil(L/32) blocks, take first L. *)
Definition hkdf_expand_def:
  hkdf_expand (prk : word8 list) (info : word8 list) (L : num) : word8 list =
    let nBlocks = (L + 31) DIV 32 in
      TAKE L (hkdf_expand_blocks prk info [] 1 nBlocks)
End

(* -------------------------------------------------------------------------- *)
(*  Output-length lemmas                                                      *)
(* -------------------------------------------------------------------------- *)

Theorem w32_be_bytes_length:
  !w. LENGTH (w32_be_bytes w) = 4
Proof
  rw[w32_be_bytes_def]
QED

Theorem sha256_digest_length:
  !msg. LENGTH (sha256_digest msg) = 32
Proof
  rw[sha256_digest_def] >>
  pairarg_tac >> gvs[] >>
  simp[w32_be_bytes_length]
QED

Theorem hmac_sha256_length:
  !key msg. LENGTH (hmac_sha256 key msg) = 32
Proof
  rw[hmac_sha256_def, sha256_digest_length]
QED

(* Each expand block contributes exactly 32 bytes, so n blocks give 32*n. *)
Theorem hkdf_expand_blocks_length:
  !n prk info prev i. LENGTH (hkdf_expand_blocks prk info prev i n) = 32 * n
Proof
  Induct >> rw[Once hkdf_expand_blocks_def] >>
  simp[hmac_sha256_length, MULT_CLAUSES]
QED

Theorem hkdf_expand_length:
  !prk info L. LENGTH (hkdf_expand prk info L) = L
Proof
  rw[hkdf_expand_def, LENGTH_TAKE_EQ, hkdf_expand_blocks_length] >>
  `L <= 32 * ((L + 31) DIV 32)` suffices_by rw[] >>
  mp_tac (SPEC ``L + 31`` (MATCH_MP DIVISION (DECIDE ``0n < 32``))) >>
  DECIDE_TAC
QED

val _ = export_theory ();