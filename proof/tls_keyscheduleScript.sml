(* tls_keyscheduleScript.sml

   HOL4 formal model of the TLS 1.3 key schedule (RFC 8446 7.1 / RFC 8448),
   Track B1 sub-worker 2. Derived from the RFC and aligned with the
   TLS_KEY_SCHEDULE signature in tls.sig, so the J4 refinement against the
   SML `TlsKeySchedule` module is mechanical.

   The model defines, as pure HOL4 functions:
     - hkdfExtract  : HKDF-Extract (RFC 5869 2.2)
     - hkdfExpand   : HKDF-Expand  (RFC 5869 2.3)
     - hkdfExpandLabel : RFC 8446 7.1
     - deriveSecret    : RFC 8446 7.1
     - earlySecret / handshakeSecret / masterSecret : the three Extract
       stages of the 1-RTT schedule
     - trafficKey / trafficIv / finishedKey : RFC 8446 7.3 / 5.2

   The underlying hash is SHA-256 (cipher suites TLS_AES_128_GCM_SHA256
   and TLS_CHACHA20_POLY1305_SHA256), matching the SML `TlsKeySchedule`
   and the RFC 8448 vectors. SHA-256, HMAC and HKDF are CONCRETE, computable
   functions here, imported from `tls_sha256Theory` (Track 2b); the RFC 8448
   key-schedule vectors are discharged by `EVAL` at the bottom of this file.
*)

open HolKernel Parse boolLib bossLib;
open listTheory optionTheory stringTheory wordsTheory;
open tls_sha256Theory;

val _ = new_theory "tls_keyschedule";

(* -------------------------------------------------------------------------- *)
(*  Trusted string/byte helpers (mechanical; replaced in Phase 7)            *)
(* -------------------------------------------------------------------------- *)

Definition string_to_word8_def:
  string_to_word8 s = MAP (\c. n2w (ORD c)) (EXPLODE s)
End

Definition w16_to_bytes_def:
  w16_to_bytes (w : word16) : word8 list =
       [w2w (w >>> 8); w2w w]
End

(* -------------------------------------------------------------------------- *)
(*  Constants                                                                 *)
(* -------------------------------------------------------------------------- *)

Definition hashLen_def:
  hashLen : num = 32   (* SHA-256 output length, in bytes *)
End

Definition zeros_def:
  zeros : word8 list = GENLIST (\_. 0w) hashLen
End

Definition deriveLabel_def:
  deriveLabel : string = "derived"
End

Definition tls13Prefix_def:
  (* "tls13 " -- the 6-byte label prefix mandated by RFC 8446 7.1. *)
  tls13Prefix : string = "tls13 "
End

(* -------------------------------------------------------------------------- *)
(*  Concrete crypto primitives (Track 2b)                                     *)
(* -------------------------------------------------------------------------- *)

(* SHA-256, HMAC-SHA-256 and HKDF-Expand are now CONCRETE, computable
   functions, taken from `tls_sha256Theory` (an independent FIPS 180-4 /
   RFC 2104 / RFC 5869 HOL4 implementation, validated by `EVAL` against the
   NIST "" and "abc" digests and against the RFC 8448 key-schedule vectors --
   see the `rfc8448_*` theorems at the bottom of this file and the
   `tls_sha256` NIST checks).  They are ordinary `Definition`s, so they carry
   NO axiom and add NO oracle; their values are pinned down and can be reduced
   by `EVAL`.

   ROUTE B note: `tls_sha256$sha256_digest` is an independent re-implementation
   of SHA-256; it is structurally aligned with the CakeML `cakeml/sha256.sml`
   source (same K constants, init vector, padding, schedule and compression)
   but is NOT yet proved equal to it by `ml_translatorLib` translation.  That
   translation link is the remaining Track 2c work (see PROOF_STATUS.md).

   The cryptographic *strength* of SHA-256/HMAC (collision/preimage
   resistance, PRF security) remains an assumption recorded in
   PROOF_STATUS.md, not a proved property. *)

(* SHA-256 : produces exactly hashLen (32) bytes. *)
Definition sha256_def:
  sha256 (bs : word8 list) : word8 list = sha256_digest bs
End

Theorem sha256_length:
  !bs. LENGTH (sha256 bs) = hashLen
Proof
  rw[sha256_def, hashLen_def, sha256_digest_length]
QED

(* HMAC-SHA-256 : keyed, produces exactly hashLen (32) bytes. *)
Definition hmac_sha256_def:
  hmac_sha256 (k : word8 list) (d : word8 list) : word8 list =
    tls_sha256$hmac_sha256 k d
End

Theorem hmac_sha256_length:
  !k d. LENGTH (hmac_sha256 k d) = hashLen
Proof
  rw[hmac_sha256_def, hashLen_def, tls_sha256Theory.hmac_sha256_length]
QED

(* HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)  (RFC 5869 2.2). *)
Definition hkdfExtract_def:
  hkdfExtract (salt : word8 list) (ikm : word8 list) : word8 list =
    hmac_sha256 salt ikm
End

(* HKDF-Expand(PRK, info, L) : RFC 5869 2.3 -- produces exactly L bytes. *)
Definition hkdfExpand_def:
  hkdfExpand (prk : word8 list) (info : word8 list) (L : num) : word8 list =
    hkdf_expand prk info L
End

Theorem hkdfExpand_length:
  !prk info L. LENGTH (hkdfExpand prk info L) = L
Proof
  rw[hkdfExpand_def, hkdf_expand_length]
QED

(* -------------------------------------------------------------------------- *)
(*  HKDF-Expand-Label (RFC 8446 7.1)                                          *)
(* -------------------------------------------------------------------------- *)

(* HkdfLabel = struct {
     length:  uint16,
     label:   opaque[length<255],   (* "tls13 " ^ label *)
     context: opaque[length<255]
   }
   wire form: [length:2][label_len:1][label][ctx_len:1][context] *)

Definition buildHkdfLabel_def:
  buildHkdfLabel (label : string) (context : word8 list) (L : num) : word8 list =
    let fullLabel = string_to_word8 (STRCAT tls13Prefix label) in
    w16_to_bytes (n2w L : word16) ++
    [n2w (LENGTH fullLabel)] ++
    fullLabel ++
    [n2w (LENGTH context)] ++
    context
End

Definition hkdfExpandLabel_def:
  hkdfExpandLabel (secret : word8 list) (label : string)
                  (context : word8 list) (L : num) : word8 list =
    hkdfExpand secret (buildHkdfLabel label context L) L
End

(* -------------------------------------------------------------------------- *)
(*  Derive-Secret (RFC 8446 7.1)                                              *)
(* -------------------------------------------------------------------------- *)

Definition deriveSecret_def:
  deriveSecret (secret : word8 list) (label : string)
               (transcript : word8 list) : word8 list =
    hkdfExpandLabel secret label (sha256 transcript) hashLen
End

(* -------------------------------------------------------------------------- *)
(*  The three Extract stages (RFC 8446 7.1)                                   *)
(* -------------------------------------------------------------------------- *)

Definition earlySecret_def:
  earlySecret (psk : word8 list) : word8 list =
    hkdfExtract zeros psk
End

Definition handshakeSecret_def:
  handshakeSecret (early : word8 list) (dhe : word8 list) : word8 list =
    hkdfExtract (deriveSecret early deriveLabel []) dhe
End

Definition masterSecret_def:
  masterSecret (handshake : word8 list) : word8 list =
    hkdfExtract (deriveSecret handshake deriveLabel []) zeros
End

(* -------------------------------------------------------------------------- *)
(*  Traffic / finished keys (RFC 8446 7.3 / 5.2)                              *)
(* -------------------------------------------------------------------------- *)

Definition trafficKey_def:
  trafficKey (secret : word8 list) (keyLength : num) : word8 list =
    hkdfExpandLabel secret "key" [] keyLength
End

Definition trafficIv_def:
  trafficIv (secret : word8 list) (ivLength : num) : word8 list =
    hkdfExpandLabel secret "iv" [] ivLength
End

Definition finishedKey_def:
  finishedKey (secret : word8 list) : word8 list =
    hkdfExpandLabel secret "finished" [] hashLen
End

(* -------------------------------------------------------------------------- *)
(*  Full 1-RTT key schedule bundle                                            *)
(* -------------------------------------------------------------------------- *)

Datatype:
  keySchedule =
    <| earlySecret           : word8 list;
       handshakeSecret       : word8 list;
       masterSecret          : word8 list;
       clientHandshakeSecret : word8 list;
       serverHandshakeSecret : word8 list;
       clientAppSecret       : word8 list;
       serverAppSecret       : word8 list |>
End

Definition schedule_def:
  schedule (dhe : word8 list)
           (handshakeTranscript : word8 list)
           (applicationTranscript : word8 list) : keySchedule =
    let e = earlySecret zeros in
    let h = handshakeSecret e dhe in
    let m = masterSecret h in
    let c_hs = deriveSecret h "c hs traffic" handshakeTranscript in
    let s_hs = deriveSecret h "s hs traffic" handshakeTranscript in
    let c_ap = deriveSecret m "c ap traffic" applicationTranscript in
    let s_ap = deriveSecret m "s ap traffic" applicationTranscript in
    <| earlySecret           := e;
       handshakeSecret       := h;
       masterSecret          := m;
       clientHandshakeSecret := c_hs;
       serverHandshakeSecret := s_hs;
       clientAppSecret       := c_ap;
       serverAppSecret       := s_ap |>
End

(* -------------------------------------------------------------------------- *)
(*  Finished verify_data (RFC 8446 4.4.4)                                     *)
(* -------------------------------------------------------------------------- *)

Definition finishedVerifyData_def:
  finishedVerifyData (fk : word8 list) (transcript : word8 list) : word8 list =
    hmac_sha256 fk (sha256 transcript)
End

(* -------------------------------------------------------------------------- *)
(*  CertificateVerify input (RFC 8446 4.4.3)                                  *)
(* -------------------------------------------------------------------------- *)

Definition certificateVerifyPrefix_def:
  certificateVerifyPrefix : word8 list = GENLIST (\_. 32w) 64
       (* 64 spaces, 0x20 *)
End

Definition certificateVerifyInput_def:
  certificateVerifyInput (contextString : word8 list)
                         (transcriptHash : word8 list) : word8 list =
    certificateVerifyPrefix ++
    contextString ++
    [32w] ++
    transcriptHash
End

Definition clientCertVerifyContext_def:
  clientCertVerifyContext : word8 list =
    string_to_word8 "TLS 1.3, client CertificateVerify"
End

Definition serverCertVerifyContext_def:
  serverCertVerifyContext : word8 list =
    string_to_word8 "TLS 1.3, server CertificateVerify"
End

(* -------------------------------------------------------------------------- *)
(*  Output-length correctness (relative to the trusted length contracts)      *)
(* -------------------------------------------------------------------------- *)

(* Each derivation produces a byte string of the RFC-mandated length.  These
   follow purely from the length contracts of the trusted primitives, so
   they are fully proved (modulo those documented assumptions). *)

Theorem hkdfExtract_length:
  !salt ikm. LENGTH (hkdfExtract salt ikm) = hashLen
Proof
  rw[hkdfExtract_def, hmac_sha256_length]
QED

Theorem hkdfExpandLabel_length:
  !secret label context L. LENGTH (hkdfExpandLabel secret label context L) = L
Proof
  rw[hkdfExpandLabel_def, hkdfExpand_length]
QED

Theorem deriveSecret_length:
  !secret label transcript. LENGTH (deriveSecret secret label transcript) = hashLen
Proof
  rw[deriveSecret_def, hkdfExpandLabel_length]
QED

Theorem earlySecret_length:
  !psk. LENGTH (earlySecret psk) = hashLen
Proof
  rw[earlySecret_def, hkdfExtract_length]
QED

Theorem handshakeSecret_length:
  !early dhe. LENGTH (handshakeSecret early dhe) = hashLen
Proof
  rw[handshakeSecret_def, hkdfExtract_length]
QED

Theorem masterSecret_length:
  !handshake. LENGTH (masterSecret handshake) = hashLen
Proof
  rw[masterSecret_def, hkdfExtract_length]
QED

Theorem trafficKey_length:
  !secret keyLength. LENGTH (trafficKey secret keyLength) = keyLength
Proof
  rw[trafficKey_def, hkdfExpandLabel_length]
QED

Theorem trafficIv_length:
  !secret ivLength. LENGTH (trafficIv secret ivLength) = ivLength
Proof
  rw[trafficIv_def, hkdfExpandLabel_length]
QED

Theorem finishedKey_length:
  !secret. LENGTH (finishedKey secret) = hashLen
Proof
  rw[finishedKey_def, hkdfExpandLabel_length]
QED

Theorem finishedVerifyData_length:
  !fk transcript. LENGTH (finishedVerifyData fk transcript) = hashLen
Proof
  rw[finishedVerifyData_def, hmac_sha256_length]
QED

(* -------------------------------------------------------------------------- *)
(*  Structural correctness: the schedule bundle follows the RFC 8446 7.1      *)
(*  Extract -> Derive -> Extract chaining exactly.                            *)
(* -------------------------------------------------------------------------- *)

(* The `schedule` bundle wires its fields exactly as the staged RFC
   derivations prescribe.  This is the "matches the RFC model" property at
   the structural level: given the same trusted primitives, the bundle is
   the 1-RTT key schedule of RFC 8446 7.1. *)
Theorem schedule_correct:
  !dhe ht at.
    let ks = schedule dhe ht at in
      (ks.earlySecret           = earlySecret zeros) /\
      (ks.handshakeSecret       = handshakeSecret ks.earlySecret dhe) /\
      (ks.masterSecret          = masterSecret ks.handshakeSecret) /\
      (ks.clientHandshakeSecret = deriveSecret ks.handshakeSecret "c hs traffic" ht) /\
      (ks.serverHandshakeSecret = deriveSecret ks.handshakeSecret "s hs traffic" ht) /\
      (ks.clientAppSecret       = deriveSecret ks.masterSecret "c ap traffic" at) /\
      (ks.serverAppSecret       = deriveSecret ks.masterSecret "s ap traffic" at)
Proof
  rw[schedule_def]
QED

(* Every secret in the schedule bundle has the SHA-256 output length. *)
Theorem schedule_lengths:
  !dhe ht at.
    let ks = schedule dhe ht at in
      (LENGTH ks.earlySecret           = hashLen) /\
      (LENGTH ks.handshakeSecret       = hashLen) /\
      (LENGTH ks.masterSecret          = hashLen) /\
      (LENGTH ks.clientHandshakeSecret = hashLen) /\
      (LENGTH ks.serverHandshakeSecret = hashLen) /\
      (LENGTH ks.clientAppSecret       = hashLen) /\
      (LENGTH ks.serverAppSecret       = hashLen)
Proof
  rw[schedule_def, earlySecret_length, handshakeSecret_length,
     masterSecret_length, deriveSecret_length]
QED

(* -------------------------------------------------------------------------- *)
(*  RFC 8448 key-schedule test vectors (discharged by EVAL)                   *)
(* -------------------------------------------------------------------------- *)

(* -------------------------------------------------------------------------- *)
(*  Fast evaluation compset for the RFC 8448 vectors                          *)
(*                                                                            *)
(*  Bare `EVAL` reduces word32 arithmetic and shifts via the default srw      *)
(*  compset, which is pathologically slow over the 64-round SHA-256 core      *)
(*  (each digest blows up into a huge number of intermediate `n2w` terms,     *)
(*  so the theory never finishes building).  We instead build a dedicated     *)
(*  `computeLib` compset that loads `wordsLib`'s fast word conversions plus    *)
(*  exactly the SHA-256 / HMAC / HKDF / key-schedule equations, and discharge *)
(*  the vectors with `CBV_CONV` over it.  This changes only the *tactic*,     *)
(*  never a definition, so it cannot affect soundness or the Track 2c         *)
(*  structural-alignment story.                                               *)
(* -------------------------------------------------------------------------- *)

val ks_cs = computeLib.new_compset [];
val _ = wordsLib.add_words_compset true ks_cs;
val _ = listSimps.list_rws ks_cs;
val _ = numposrepLib.add_numposrep_compset ks_cs;
val _ = computeLib.add_thms
  [ (* SHA-256 core (tls_sha256Theory) *)
    sha256_digest_def, processBlocks_def, processBlock_def,
    tls_sha256Theory.schedule_def, extendW_def, compress_round_def,
    chunk16_def, split16_def, bytes_to_words_def, bytes_to_w32_def,
    sha_pad_def, padZeros_def, w64_be_bytes_def, w32_be_bytes_def,
    initState_def, kConstants_def, initHash_def, rotr32_def,
    sigma0_def, sigma1_def, bigsigma0_def, bigsigma1_def, ch_def, maj_def,
    (* HMAC + HKDF (tls_sha256Theory) *)
    tls_sha256Theory.hmac_sha256_def, hmacKey_def, xorPad_def, shaBlockSize_def,
    hkdf_extract_def, hkdf_expand_def, hkdf_expand_blocks_def,
    (* key-schedule layer (this theory) *)
    sha256_def, hmac_sha256_def, hkdfExtract_def, hkdfExpand_def,
    hkdfExpandLabel_def, buildHkdfLabel_def, deriveSecret_def,
    earlySecret_def, handshakeSecret_def, masterSecret_def,
    deriveLabel_def, tls13Prefix_def, hashLen_def, zeros_def,
    string_to_word8_def, w16_to_bytes_def ] ks_cs;

(* Conversion + tactic that reduce a closed key-schedule term to its bytes.
   `KS_EVAL` normalises word literals to decimal (`51w`); the goal's RHS is
   written in hex (`0x33w`).  Rather than depend on a common literal form for
   `REFL_TAC`, we evaluate the entire boolean equation `lhs = rhs` to `T`
   (the `wordsLib` compset decides word-list equality), which is insensitive
   to the hex-vs-decimal surface syntax. *)
(* Conversion + tactic that discharge a closed key-schedule vector.
   `KS_EVAL` (fast `wordsLib`-backed compset) reduces the LHS computation to a
   concrete byte list quickly; a final `EVAL` then decides the resulting
   all-literal list equality to `T` (insensitive to hex-vs-decimal surface
   syntax, as both denote the same `n2w` terms).  Only the *tactic* changes;
   no definition is touched, so soundness and the Track 2c alignment story
   are unaffected. *)
val KS_EVAL = computeLib.CBV_CONV ks_cs;
fun KS_VEC_TAC g = (CONV_TAC (LAND_CONV KS_EVAL) THEN CONV_TAC EVAL) g;

(* These pin the concrete `tls_sha256`-backed key schedule to the published
   byte vectors of RFC 8448 ("Example Handshake Traces for TLS 1.3").  They
   are closed by `EVAL` (computation), not by `cheat` -- which is only
   possible now that `sha256`/`hmac_sha256`/`hkdfExpand` are concrete.

   Both targets are fully determined by constants in this theory (no external
   transcript needed):

   * Early Secret  = HKDF-Extract(0_32, 0_32)               [RFC 8448 p.4]
   * Derived (for handshake) = Derive-Secret(EarlySecret, "derived", "")
     i.e. HKDF-Expand-Label(EarlySecret, "derived", H(""), 32)  [RFC 8448 p.4]
*)

(* STUB (TDD): asserted first, discharged below. *)
Theorem rfc8448_early_secret:
  earlySecret zeros =
    [0x33w; 0xadw; 0x0aw; 0x1cw; 0x60w; 0x7ew; 0xc0w; 0x3bw;
     0x09w; 0xe6w; 0xcdw; 0x98w; 0x93w; 0x68w; 0x0cw; 0xe2w;
     0x10w; 0xadw; 0xf3w; 0x00w; 0xaaw; 0x1fw; 0x26w; 0x60w;
     0xe1w; 0xb2w; 0x2ew; 0x10w; 0xf1w; 0x70w; 0xf9w; 0x2aw]
Proof
  KS_VEC_TAC
QED

Theorem rfc8448_derived_secret:
  deriveSecret (earlySecret zeros) deriveLabel [] =
    [0x6fw; 0x26w; 0x15w; 0xa1w; 0x08w; 0xc7w; 0x02w; 0xc5w;
     0x67w; 0x8fw; 0x54w; 0xfcw; 0x9dw; 0xbaw; 0xb6w; 0x97w;
     0x16w; 0xc0w; 0x76w; 0x18w; 0x9cw; 0x48w; 0x25w; 0x0cw;
     0xebw; 0xeaw; 0xc3w; 0x57w; 0x6cw; 0x36w; 0x11w; 0xbaw]
Proof
  KS_VEC_TAC
QED

val _ = export_theory ();
