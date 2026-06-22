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
   and the RFC 8448 vectors. SHA-256, HMAC, and HKDF are taken as trusted
   primitives here (Phase 7 either ports a verified SHA-256 from the
   CakeML tower or documents each as a trusted axiom).
*)

open HolKernel Parse boolLib bossLib;
open listTheory optionTheory stringTheory wordsTheory;

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
(*  Trusted crypto primitives                                                 *)
(* -------------------------------------------------------------------------- *)

(* SHA-256, HMAC-SHA-256 and HKDF-Expand are modeled as TRUSTED, abstract
   primitives.  We do NOT define their values (so nothing false about their
   contents can be derived); we only pin down their output-length contracts,
   which is all the key-schedule correctness arguments below rely on.

   These are introduced by `new_specification`, a *conservative* (sound)
   extension -- the existence witness is the constant-length function -- so
   they carry NO axiom tag.  The cryptographic strength of SHA-256/HMAC
   (collision/preimage resistance, PRF security) is an assumption recorded
   in PROOF_STATUS.md, not a proved property.  A future refinement would
   link `sha256` to a verified bit-level SHA-256 (e.g. from the CakeML
   tower) and discharge the RFC 8448 test vectors against it. *)

(* SHA-256 : produces exactly hashLen (32) bytes. *)
Theorem sha256_exists[local]:
  ?f : word8 list -> word8 list. !bs. LENGTH (f bs) = hashLen
Proof
  Q.EXISTS_TAC `\bs. GENLIST (\_. 0w) hashLen` >> simp[]
QED
val sha256_length =
  new_specification ("sha256_length", ["sha256"], sha256_exists);

(* HMAC-SHA-256 : keyed, produces exactly hashLen (32) bytes. *)
Theorem hmac_sha256_exists[local]:
  ?f : word8 list -> word8 list -> word8 list. !k d. LENGTH (f k d) = hashLen
Proof
  Q.EXISTS_TAC `\k d. GENLIST (\_. 0w) hashLen` >> simp[]
QED
val hmac_sha256_length =
  new_specification ("hmac_sha256_length", ["hmac_sha256"], hmac_sha256_exists);

(* HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)  (RFC 5869 2.2). *)
Definition hkdfExtract_def:
  hkdfExtract (salt : word8 list) (ikm : word8 list) : word8 list =
    hmac_sha256 salt ikm
End

(* HKDF-Expand(PRK, info, L) : RFC 5869 2.3 -- produces exactly L bytes.
   The HMAC iteration is abstracted; only the output length is specified. *)
Theorem hkdfExpand_exists[local]:
  ?f : word8 list -> word8 list -> num -> word8 list. !prk info L. LENGTH (f prk info L) = L
Proof
  Q.EXISTS_TAC `\prk info L. GENLIST (\_. 0w) L` >> simp[]
QED
val hkdfExpand_length =
  new_specification ("hkdfExpand_length", ["hkdfExpand"], hkdfExpand_exists);

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

val _ = export_theory ();
