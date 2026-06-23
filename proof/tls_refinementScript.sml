(* tls_refinementScript.sml

   Track 2c: mechanized refinement linking the CakeML implementation
   (cakeml/tls.sml) to the HOL4 wire spec (tls_wireTheory).

   GOAL.  The CakeML port and the HOL4 spec model the SAME RFC 8446 wire
   codecs but in two different surface representations:

     - the HOL4 spec (tls_wireTheory) works on records over ``:word8 list``
       and ``:word16`` and uses HOL word arithmetic;
     - the CakeML port (cakeml/tls.sml) has NO records and NO Word16/Word32,
       so every structure is a tuple, every multi-byte integer is a native
       ``int`` (de)serialized by ``div``/``mod`` and ``*256+``, and every
       byte string is a ``string`` of chars in 0..255 manipulated through
       ``String.size`` / ``String.sub`` / ``String.substring`` /
       ``String.extract`` / ``Char.ord`` / ``Char.chr``.

   This theory MIRRORS, by hand in HOL4, the CakeML codec functions exactly
   as written in cakeml/tls.sml --- same tuple shapes, same ``div``/``mod``
   arithmetic, same length guards --- on a faithful representation of the
   CakeML value space:

     - a CakeML byte ``int`` in 0..255 is modeled as a HOL ``:num``;
     - a CakeML ``string`` of such bytes is modeled as a HOL ``:num list``;
       ``String.size`` = ``LENGTH``, ``String.sub s i`` = ``EL i s``,
       ``String.substring s i n`` = ``TAKE n (DROP i s)``,
       ``String.extract s i None`` = ``DROP i s``, ``s ^ t`` = ``s ++ t``,
       ``String.implode`` of a char list = that ``num list``,
       ``Char.ord``/``Char.chr`` are the identity on the 0..255 range.

   We then prove that this hand-mirrored CakeML codec EQUALS the
   tls_wireTheory spec codec, transported across the representation map

       b2n  = w2n        : word8 -> num            (byte  -> CakeML int)
       s2ns = MAP w2n    : word8 list -> num list  (bytes -> CakeML string)

   so that the Track 2a round-trip theorems transfer to the CakeML-shaped
   functions.

   HONESTY NOTE (translator-certification gap).  These equalities are proved
   against a BY-HAND HOL4 mirror of cakeml/tls.sml, not against an
   ml_translatorLib-certified deep embedding of the actual CakeML AST.
   Integrating the full CakeML translator build (which deep-embeds the source
   and produces a certificate theorem relating the HOL function to the CakeML
   semantics) is heavy and was out of scope for this session; that link --
   "the HOL mirror below is the function ml_translatorLib extracts from
   cakeml/tls.sml" -- remains as the final step of Track 2c.  What is proved
   here is the mathematically substantive half: the CakeML-shaped arithmetic
   /control-flow codec computes exactly the spec codec under the byte
   representation map. *)

open HolKernel Parse boolLib bossLib;
open listTheory rich_listTheory optionTheory wordsTheory wordsLib arithmeticTheory;
open tls_wireTheory tls_handshakeTheory;

val _ = new_theory "tls_refinement";

(* -------------------------------------------------------------------------- *)
(*  Representation map: spec word8 bytes  <->  CakeML int/string bytes        *)
(* -------------------------------------------------------------------------- *)

(* A spec byte is a word8; the CakeML mirror represents the same byte as the
   num w2n of it (CakeML's Char.ord . the char). *)
Definition b2n_def:
  b2n (w : word8) : num = w2n w
End

(* A spec byte string is a word8 list; CakeML represents it as the num list
   of ord-values. *)
Definition s2ns_def:
  s2ns (bs : word8 list) : num list = MAP w2n bs
End

(* -------------------------------------------------------------------------- *)
(*  contentType (cakeml/tls.sml: contentTypeToByte / byteToContentType)       *)
(* -------------------------------------------------------------------------- *)

(* Hand-mirror of CakeML `contentTypeToByte` (returns a CakeML int byte). The
   CakeML datatype `contentType` has the SAME constructors as the spec, so we
   reuse the spec datatype and only mirror the byte arithmetic. *)
Definition cml_contentTypeToByte_def:
  (cml_contentTypeToByte Invalid          = 0n) /\
  (cml_contentTypeToByte ChangeCipherSpec = 20n) /\
  (cml_contentTypeToByte Alert            = 21n) /\
  (cml_contentTypeToByte Handshake        = 22n) /\
  (cml_contentTypeToByte ApplicationData  = 23n)
End

(* Hand-mirror of CakeML `byteToContentType` (takes a CakeML int byte). *)
Definition cml_byteToContentType_def:
  cml_byteToContentType (b : num) : contentType option =
    if b = 0   then SOME Invalid
    else if b = 20 then SOME ChangeCipherSpec
    else if b = 21 then SOME Alert
    else if b = 22 then SOME Handshake
    else if b = 23 then SOME ApplicationData
    else NONE
End

(* The CakeML encoder equals the spec encoder transported through b2n. *)
Theorem cml_contentTypeToByte_refines:
  !ct. cml_contentTypeToByte ct = b2n (encodeContentType ct)
Proof
  Cases >> EVAL_TAC
QED

(* The CakeML decoder equals the spec decoder transported through b2n. *)
Theorem w2n_eq_small:
  !(w:word8) k. k < 256 ==> ((w2n w = k) <=> (w = n2w k))
Proof
  rw[] >> eq_tac >> rw[] >>
  `dimword (:8) = 256` by EVAL_TAC >>
  metis_tac[w2n_n2w, n2w_w2n, LESS_MOD]
QED

Theorem cml_byteToContentType_refines:
  !w. cml_byteToContentType (b2n w) = decodeContentType w
Proof
  rw[cml_byteToContentType_def, decodeContentType_def, b2n_def] >>
  fs[w2n_eq_small]
QED

(* -------------------------------------------------------------------------- *)
(*  plaintext (cakeml/tls.sml: encodePlaintext / decodePlaintext)             *)
(* -------------------------------------------------------------------------- *)

(* CakeML legacyVersion = 0x0303, used as a plain int. *)
Definition cml_legacyVersion_def:
  cml_legacyVersion : num = 0x0303n
End

(* Hand-mirror of CakeML `encodePlaintext (ct, fragment)`.  A CakeML
   tlsPlaintext is the tuple (contentType, fragment:string); we model the
   fragment as a num list.  The body follows cakeml/tls.sml line-for-line:
     hdr = [ ctByte, ver div 256, ver mod 256, n div 256, n mod 256 ]
     result = hdr ^ fragment. *)
Definition cml_encodePlaintext_def:
  cml_encodePlaintext (ct, (fragment : num list)) : num list =
    let n = LENGTH fragment in
      [ cml_contentTypeToByte ct;
        cml_legacyVersion DIV 256; cml_legacyVersion MOD 256;
        n DIV 256; n MOD 256 ] ++ fragment
End

(* Hand-mirror of CakeML `decodePlaintext s` over a num list. *)
Definition cml_decodePlaintext_def:
  cml_decodePlaintext (s : num list) : ((contentType # num list) # num list) option =
    if LENGTH s < 5 then NONE
    else
      let b0 = EL 0 s in
      let hi = EL 3 s in
      let lo = EL 4 s in
      let n  = hi * 256 + lo in
        case cml_byteToContentType b0 of
          NONE => NONE
        | SOME ct =>
            if LENGTH s < 5 + n then NONE
            else
              let frag = TAKE n (DROP 5 s) in
              let rest = DROP (5 + n) s in
                SOME ((ct, frag), rest)
End

(* Representation of a spec tlsPlaintext record as the CakeML tuple. *)
Definition reprPlaintext_def:
  reprPlaintext (r : tlsPlaintext) = (r.contentType, s2ns r.fragment)
End

(* The CakeML div/mod byte split of a length < 2^16 equals the spec's
   word-based hi/lo byte split, read back through w2n.  This is the
   arithmetic core that makes the encoders agree. *)
Theorem w16_split_refines:
  !n. n < 65536 ==>
      n DIV 256 = w2n (w8_of_w16_hi (n2w n : word16)) /\
      n MOD 256 = w2n (w8_of_w16_lo (n2w n : word16))
Proof
  rpt strip_tac >>
  simp[w8_of_w16_hi_def, w8_of_w16_lo_def, w2w_def, w2n_lsr, w2n_n2w] >>
  `dimword (:16) = 65536` by EVAL_TAC >>
  `dimword (:8) = 256` by EVAL_TAC >>
  simp[] >>
  `n DIV 256 < 256` by simp[DIV_LT_X] >>
  simp[LESS_MOD]
QED

(* The CakeML encoder, applied to the CakeML tuple representing r, produces
   exactly the byte-string representation of the spec encoder's output. *)
Theorem cml_encodePlaintext_refines:
  !r. LENGTH r.fragment < 65536 ==>
      cml_encodePlaintext (reprPlaintext r) = s2ns (encodePlaintext r)
Proof
  rw[cml_encodePlaintext_def, reprPlaintext_def, encodePlaintext_def,
     s2ns_def, w16_to_bytes_def, cml_legacyVersion_def, legacyVersion_def] >>
  simp[cml_contentTypeToByte_refines, b2n_def] >>
  `LENGTH r.fragment DIV 256 = w2n (w8_of_w16_hi (n2w (LENGTH r.fragment):word16)) /\
   LENGTH r.fragment MOD 256 = w2n (w8_of_w16_lo (n2w (LENGTH r.fragment):word16))`
    by simp[w16_split_refines] >>
  simp[] >> EVAL_TAC
QED

(* The CakeML decoder, applied to the byte-string representation of the spec
   input, produces the CakeML-tuple representation of the spec decoder's
   output. *)
(* The big-endian 2-byte length read in the CakeML decoder (hi*256 + lo over
   CakeML int bytes) equals the spec's word-based w16_of_bytes read, through
   the byte representation map.  This is the arithmetic core that makes the
   decoders agree on the length field. *)
Theorem w16_read_refines:
  !(hi:word8) (lo:word8). w2n hi * 256 + w2n lo = w2n (w16_of_bytes hi lo)
Proof
  rpt strip_tac >>
  `w2n hi < 256` by (assume_tac (Q.ISPEC `hi:word8` w2n_lt) >> fs[]) >>
  `w2n lo < 256` by (assume_tac (Q.ISPEC `lo:word8` w2n_lt) >> fs[]) >>
  `w16_of_bytes hi lo = w2w hi * 256w + (w2w lo : word16)` by
      (rw[w16_of_bytes_def] >> blastLib.BBLAST_TAC) >>
  pop_assum SUBST1_TAC >>
  `(w2w hi : word16) = n2w (w2n hi)` by
      (rw[w2w_def] >> `dimword(:16)=65536` by EVAL_TAC >> simp[LESS_MOD]) >>
  `(w2w lo : word16) = n2w (w2n lo)` by
      (rw[w2w_def] >> `dimword(:16)=65536` by EVAL_TAC >> simp[LESS_MOD]) >>
  ntac 2 (pop_assum (fn th => REWRITE_TAC[th])) >>
  REWRITE_TAC[word_mul_n2w, word_add_n2w] >>
  `w2n hi * 256 + w2n lo < 65536` by DECIDE_TAC >>
  simp[w2n_n2w] >> `dimword(:16)=65536` by EVAL_TAC >> simp[LESS_MOD]
QED

(* The CakeML decoder, applied to the byte-string representation of the spec
   input, produces the CakeML-tuple representation of the spec decoder's
   output. *)
Theorem cml_decodePlaintext_refines:
  !bs. cml_decodePlaintext (s2ns bs) =
       OPTION_MAP (\(r, rest). (reprPlaintext r, s2ns rest)) (decodePlaintext bs)
Proof
  rw[cml_decodePlaintext_def, decodePlaintext_def, s2ns_def] >>
  fs[LENGTH_MAP] >>
  `bs <> []` by (Cases_on `bs` >> fs[]) >>
  `HD (MAP w2n bs) = w2n (HD bs)` by (Cases_on `bs` >> fs[]) >>
  `EL 3 (MAP w2n bs) = w2n (EL 3 bs)` by (irule EL_MAP >> simp[]) >>
  `EL 4 (MAP w2n bs) = w2n (EL 4 bs)` by (irule EL_MAP >> simp[]) >>
  simp[] >>
  `cml_byteToContentType (w2n (HD bs)) = decodeContentType (HD bs)`
    by metis_tac[cml_byteToContentType_refines, b2n_def] >>
  `w2n (EL 3 bs) * 256 + w2n (EL 4 bs) = w2n (w16_of_bytes (EL 3 bs) (EL 4 bs))`
    by simp[w16_read_refines] >>
  simp[] >>
  Cases_on `decodeContentType (HD bs)` >> simp[] >>
  rw[] >> fs[] >>
  `256 * w2n (EL 3 bs) + (w2n (EL 4 bs) + 5) = w2n (w16_of_bytes (EL 3 bs) (EL 4 bs)) + 5`
    by (qpat_x_assum `_ = w2n (w16_of_bytes _ _)` mp_tac >> DECIDE_TAC) >>
  simp[reprPlaintext_def, s2ns_def, MAP_TAKE, MAP_DROP] >>
  rw[tls_wireTheory.tlsPlaintext_component_equality] >>
  simp[MAP_TAKE, MAP_DROP]
QED

(* -------------------------------------------------------------------------- *)
(*  ciphertext (cakeml/tls.sml: encodeCiphertext / decodeCiphertext)          *)
(* -------------------------------------------------------------------------- *)

(* CakeML defines encodeCiphertext = encodePlaintext and
   decodeCiphertext = decodePlaintext (identical framing). *)
Definition cml_encodeCiphertext_def:
  cml_encodeCiphertext (ct, (encryptedRecord : num list)) : num list =
    cml_encodePlaintext (ct, encryptedRecord)
End

Definition cml_decodeCiphertext_def:
  cml_decodeCiphertext (s : num list) = cml_decodePlaintext s
End

Definition reprCiphertext_def:
  reprCiphertext (r : tlsCiphertext) = (r.contentType, s2ns r.encryptedRecord)
End

Theorem cml_encodeCiphertext_refines:
  !r. LENGTH r.encryptedRecord < 65536 ==>
      cml_encodeCiphertext (reprCiphertext r) = s2ns (encodeCiphertext r)
Proof
  rw[cml_encodeCiphertext_def, cml_encodePlaintext_def, reprCiphertext_def,
     encodeCiphertext_def, s2ns_def, w16_to_bytes_def, cml_legacyVersion_def,
     legacyVersion_def] >>
  simp[cml_contentTypeToByte_refines, b2n_def] >>
  `LENGTH r.encryptedRecord DIV 256 =
     w2n (w8_of_w16_hi (n2w (LENGTH r.encryptedRecord):word16)) /\
   LENGTH r.encryptedRecord MOD 256 =
     w2n (w8_of_w16_lo (n2w (LENGTH r.encryptedRecord):word16))`
    by simp[w16_split_refines] >>
  simp[] >> EVAL_TAC
QED

(* The CakeML ciphertext decoder, applied to the byte-string representation of
   the spec input, produces the CakeML-tuple representation of the spec
   ciphertext decoder's output.  Mirrors `cml_decodePlaintext_refines`: the
   CakeML framing is byte-for-byte identical (decodeCiphertext = decodePlaintext
   in cakeml/tls.sml), and the spec decodeCiphertext has the same body as
   decodePlaintext modulo the record field name (encryptedRecord vs fragment). *)
Theorem cml_decodeCiphertext_refines:
  !bs. cml_decodeCiphertext (s2ns bs) =
       OPTION_MAP (\(r, rest). (reprCiphertext r, s2ns rest)) (decodeCiphertext bs)
Proof
  rw[cml_decodeCiphertext_def, cml_decodePlaintext_def, decodeCiphertext_def,
     s2ns_def] >>
  fs[LENGTH_MAP] >>
  `bs <> []` by (Cases_on `bs` >> fs[]) >>
  `HD (MAP w2n bs) = w2n (HD bs)` by (Cases_on `bs` >> fs[]) >>
  `EL 3 (MAP w2n bs) = w2n (EL 3 bs)` by (irule EL_MAP >> simp[]) >>
  `EL 4 (MAP w2n bs) = w2n (EL 4 bs)` by (irule EL_MAP >> simp[]) >>
  simp[] >>
  `cml_byteToContentType (w2n (HD bs)) = decodeContentType (HD bs)`
    by metis_tac[cml_byteToContentType_refines, b2n_def] >>
  `w2n (EL 3 bs) * 256 + w2n (EL 4 bs) = w2n (w16_of_bytes (EL 3 bs) (EL 4 bs))`
    by simp[w16_read_refines] >>
  simp[] >>
  Cases_on `decodeContentType (HD bs)` >> simp[] >>
  rw[] >> fs[] >>
  `256 * w2n (EL 3 bs) + (w2n (EL 4 bs) + 5) = w2n (w16_of_bytes (EL 3 bs) (EL 4 bs)) + 5`
    by (qpat_x_assum `_ = w2n (w16_of_bytes _ _)` mp_tac >> DECIDE_TAC) >>
  simp[reprCiphertext_def, s2ns_def, MAP_TAKE, MAP_DROP] >>
  rw[tls_wireTheory.tlsCiphertext_component_equality] >>
  simp[MAP_TAKE, MAP_DROP]
QED

(* -------------------------------------------------------------------------- *)
(*  Shared structured-codec helpers (cakeml/tls.sml: word16ToBytes,           *)
(*  encodeExtensions, encodeWord16List, encodeWord8List, len3, word32ToBytes) *)
(* -------------------------------------------------------------------------- *)

(* SCOPE / HONESTY (structured codecs).  The clientHello/serverHello/
   certificate/newSessionTicket codecs are nested and length-prefixed, so the
   CakeML decoders are recursive, exception-driven byte parsers whose control
   flow (the `Bad`/`handle` mechanism, the index-based `String.sub`/`substring`
   re-reads, the `csTotal div 2` cipher-suite count, the self-describing
   extension blocks) diverges substantially from the spec's structural,
   remainder-passing decoders.  We therefore refine the ENCODE direction of all
   four structured codecs SOUNDLY and IN FULL (each `cml_encode<X>` hand-mirror
   is proved EQUAL to `s2ns (encode<X> r)` under the same honest wire
   length-bound side conditions `wf<X>` that Track 2a uses).  The encode
   refinements compose with the Track 2a round-trip theorems
   (`decode_encode_<X>`), so they pin down the on-the-wire byte string the
   CakeML port emits is exactly the spec's.  The recursive CakeML decoders'
   full equational refinement is heavier (it needs a mirror of the `Bad`
   exception monad and the index arithmetic) and is left as honest remaining
   work rather than discharged unsoundly. *)

(* Hand-mirror of CakeML `word16ToBytes` over a CakeML int. *)
Definition cml_word16ToBytes_def:
  cml_word16ToBytes (w : num) : num list = [(w DIV 256) MOD 256; w MOD 256]
End

(* The CakeML `word16ToBytes` of the int representing a spec word16 equals the
   spec's `w16_to_bytes`, read back through s2ns. *)
Theorem cml_word16ToBytes_refines:
  !w:word16. cml_word16ToBytes (w2n w) = s2ns (w16_to_bytes w)
Proof
  rw[cml_word16ToBytes_def, s2ns_def, w16_to_bytes_def] >>
  `w2n w < 65536` by (assume_tac (Q.ISPEC `w:word16` w2n_lt) >>
                      `dimword (:16) = 65536` by EVAL_TAC >> fs[]) >>
  `(w2n w DIV 256) MOD 256 = w2n w DIV 256`
    by (`w2n w DIV 256 < 256` by simp[DIV_LT_X] >> simp[LESS_MOD]) >>
  `(n2w (w2n w) : word16) = w` by simp[n2w_w2n] >>
  metis_tac[w16_split_refines]
QED

(* Hand-mirror of CakeML `word32ToBytes` over a CakeML int. *)
Definition cml_word32ToBytes_def:
  cml_word32ToBytes (w : num) : num list =
    [(w DIV 16777216) MOD 256; (w DIV 65536) MOD 256;
     (w DIV 256) MOD 256; w MOD 256]
End

(* The CakeML `word32ToBytes` of the int representing a spec word32 equals the
   spec's `w32_to_bytes`, read back through s2ns. *)
Theorem cml_word32ToBytes_refines:
  !w:word32. cml_word32ToBytes (w2n w) = s2ns (w32_to_bytes w)
Proof
  rw[cml_word32ToBytes_def, s2ns_def, w32_to_bytes_def] >>
  `dimword (:32) = 4294967296` by EVAL_TAC >>
  `dimword (:8) = 256` by EVAL_TAC >>
  `w2n w < 4294967296` by (assume_tac (Q.ISPEC `w:word32` w2n_lt) >> fs[]) >>
  rpt conj_tac
  >- (simp[w2w_def, w2n_lsr] >>
      `w2n w DIV 16777216 < 256` by simp[DIV_LT_X] >> simp[LESS_MOD])
  >- (simp[w2w_def, w2n_lsr] >>
      `(w2n w DIV 65536) MOD 256 = (w2n w DIV 65536) MOD dimword (:8)` by simp[] >>
      simp[] >> AP_THM_TAC >> AP_TERM_TAC >> simp[])
  >- (simp[w2w_def, w2n_lsr] >>
      `(w2n w DIV 256) MOD 256 = (w2n w DIV 256) MOD dimword (:8)` by simp[] >>
      simp[])
  >- (simp[w2w_def] >> `w2n w MOD 256 = w2n w MOD dimword (:8)` by simp[] >> simp[])
QED

(* Hand-mirror of CakeML `len3` over a CakeML int. *)
Definition cml_len3_def:
  cml_len3 (n : num) : num list =
    [(n DIV 65536) MOD 256; (n DIV 256) MOD 256; n MOD 256]
End

(* The CakeML `len3` split equals the spec's `len3`, read back through s2ns,
   for a length < 2^24. *)
Theorem cml_len3_refines:
  !n. n < 16777216 ==> cml_len3 n = s2ns (len3 n)
Proof
  rw[cml_len3_def, s2ns_def, len3_def] >>
  `dimword (:8) = 256` by EVAL_TAC >>
  rpt conj_tac >> simp[w2n_n2w] >>
  (TRY (`(n DIV 65536) MOD 256 < 256` by simp[] >> NO_TAC)) >>
  metis_tac[]
QED

(* Hand-mirror of CakeML `encodeExtensions`.  A CakeML extension is the tuple
   (extType:int, data:string) modeled as (num # num list).  The body is the
   concatenation of [word16ToBytes et ^ word16ToBytes (size d) ^ d] and the
   header is word16ToBytes of the total body length. *)
Definition cml_encodeExtensionBody_def:
  cml_encodeExtensionBody ((et, d) : num # num list) : num list =
    cml_word16ToBytes et ++ cml_word16ToBytes (LENGTH d) ++ d
End

Definition cml_encodeExtensions_def:
  cml_encodeExtensions (exts : (num # num list) list) : num list =
    let body = FLAT (MAP cml_encodeExtensionBody exts) in
      cml_word16ToBytes (LENGTH body) ++ body
End

(* Representation of a spec extension record as the CakeML (int, string) tuple. *)
Definition reprExt_def:
  reprExt (e : extension) : num # num list = (w2n e.extType, s2ns e.data)
End

(* A single encoded extension refines, given the data fits a 2-byte length. *)
Theorem cml_encodeExtensionBody_refines:
  !e. LENGTH e.data < 65536 ==>
      cml_encodeExtensionBody (reprExt e) = s2ns (encodeExtension e)
Proof
  rw[cml_encodeExtensionBody_def, reprExt_def, encodeExtension_def, s2ns_def] >>
  simp[GSYM s2ns_def, cml_word16ToBytes_refines] >>
  `cml_word16ToBytes (LENGTH e.data) =
     s2ns (w16_to_bytes (n2w (LENGTH e.data) : word16))`
    by (`(w2n (n2w (LENGTH e.data) : word16)) = LENGTH e.data`
          by (simp[w2n_n2w] >> `dimword (:16) = 65536` by EVAL_TAC >> simp[]) >>
        metis_tac[cml_word16ToBytes_refines]) >>
  simp[s2ns_def]
QED

(* The CakeML extension-body concatenation refines the spec's
   FLAT (MAP encodeExtension es), under the per-extension data bound. *)
Theorem cml_encodeExtensionBody_list_refines:
  !es. EVERY (\e. LENGTH e.data < 65536) es ==>
       FLAT (MAP cml_encodeExtensionBody (MAP reprExt es)) =
       s2ns (FLAT (MAP encodeExtension es))
Proof
  Induct >> simp[s2ns_def] >>
  rpt strip_tac >> fs[] >>
  simp[GSYM s2ns_def] >>
  `cml_encodeExtensionBody (reprExt h) = s2ns (encodeExtension h)`
    by simp[cml_encodeExtensionBody_refines] >>
  simp[s2ns_def]
QED

(* The full CakeML `encodeExtensions` refines the spec `encodeExtensions`,
   under the same two honest bounds Track 2a uses. *)
Theorem cml_encodeExtensions_refines:
  !es. EVERY (\e. LENGTH e.data < 65536) es /\
       LENGTH (FLAT (MAP encodeExtension es)) < 65536 ==>
       cml_encodeExtensions (MAP reprExt es) = s2ns (encodeExtensions es)
Proof
  rw[cml_encodeExtensions_def, encodeExtensions_def] >>
  `FLAT (MAP cml_encodeExtensionBody (MAP reprExt es)) =
     s2ns (FLAT (MAP encodeExtension es))`
    by simp[cml_encodeExtensionBody_list_refines] >>
  `LENGTH (FLAT (MAP cml_encodeExtensionBody (MAP reprExt es))) =
     LENGTH (FLAT (MAP encodeExtension es))`
    by (pop_assum (fn th => REWRITE_TAC[th]) >> simp[s2ns_def]) >>
  ntac 2 (pop_assum mp_tac) >> rw[] >>
  `cml_word16ToBytes (LENGTH (FLAT (MAP encodeExtension es))) =
     s2ns (w16_to_bytes (n2w (LENGTH (FLAT (MAP encodeExtension es))) : word16))`
    by (`(w2n (n2w (LENGTH (FLAT (MAP encodeExtension es))) : word16)) =
           LENGTH (FLAT (MAP encodeExtension es))`
          by (simp[w2n_n2w] >> `dimword (:16) = 65536` by EVAL_TAC >> simp[]) >>
        metis_tac[cml_word16ToBytes_refines]) >>
  simp[s2ns_def]
QED

(* Hand-mirror of CakeML `encodeWord16List` (the cipher-suite list of a
   ClientHello): a 2-byte length prefix (= 2 * count) then the concatenated
   2-byte encodings. *)
Definition cml_encodeWord16ListBody_def:
  cml_encodeWord16ListBody (ws : num list) : num list =
    FLAT (MAP cml_word16ToBytes ws)
End

Definition cml_encodeWord16List_def:
  cml_encodeWord16List (ws : num list) : num list =
    cml_word16ToBytes (LENGTH (cml_encodeWord16ListBody ws)) ++
    cml_encodeWord16ListBody ws
End

(* The CakeML word16-list body refines the spec body, for a list of word16s. *)
Theorem cml_encodeWord16ListBody_refines:
  !ws. cml_encodeWord16ListBody (MAP w2n ws) = s2ns (encodeW16ListBody ws)
Proof
  Induct >> simp[cml_encodeWord16ListBody_def, encodeW16ListBody_def, s2ns_def] >>
  rpt strip_tac >>
  fs[cml_encodeWord16ListBody_def, encodeW16ListBody_def] >>
  simp[GSYM s2ns_def, cml_word16ToBytes_refines] >>
  simp[s2ns_def]
QED

(* The full CakeML `encodeWord16List` refines the spec `encodeW16List`, under
   the honest bound that the body length (2 * count) fits the 2-byte prefix. *)
Theorem cml_encodeWord16List_refines:
  !ws. 2 * LENGTH ws < 65536 ==>
       cml_encodeWord16List (MAP w2n ws) = s2ns (encodeW16List ws)
Proof
  rw[cml_encodeWord16List_def, encodeW16List_def] >>
  `cml_encodeWord16ListBody (MAP w2n ws) = s2ns (encodeW16ListBody ws)`
    by simp[cml_encodeWord16ListBody_refines] >>
  `LENGTH (cml_encodeWord16ListBody (MAP w2n ws)) =
     LENGTH (encodeW16ListBody ws)`
    by (pop_assum (fn th => REWRITE_TAC[th]) >> simp[s2ns_def]) >>
  ntac 2 (pop_assum mp_tac) >> rw[] >>
  `LENGTH (encodeW16ListBody ws) = 2 * LENGTH ws`
    by simp[encodeW16ListBody_length] >>
  `cml_word16ToBytes (LENGTH (encodeW16ListBody ws)) =
     s2ns (w16_to_bytes (n2w (LENGTH (encodeW16ListBody ws)) : word16))`
    by (`(w2n (n2w (LENGTH (encodeW16ListBody ws)) : word16)) =
           LENGTH (encodeW16ListBody ws)`
          by (simp[w2n_n2w, encodeW16ListBody_length] >>
              `dimword (:16) = 65536` by EVAL_TAC >> simp[]) >>
        metis_tac[cml_word16ToBytes_refines]) >>
  simp[s2ns_def]
QED

(* -------------------------------------------------------------------------- *)
(*  ServerHello encode (cakeml/tls.sml: encodeServerHello)                     *)
(* -------------------------------------------------------------------------- *)

(* Hand-mirror of CakeML `encodeServerHello (legacyVersion, random,
   legacySessionId, cipherSuite, legacyCompression, extensions)`.  legacyVersion
   and cipherSuite are CakeML ints (word16), legacyCompression is a CakeML int
   (single byte), random/legacySessionId are CakeML strings (num lists),
   extensions is a (int * string) list. *)
Definition cml_encodeServerHello_def:
  cml_encodeServerHello ((legacyVersion, random, legacySessionId,
                          cipherSuite, legacyCompression, extensions)
                         : num # num list # num list # num #
                           num # (num # num list) list) : num list =
    cml_word16ToBytes legacyVersion ++
    random ++
    (LENGTH legacySessionId :: legacySessionId) ++
    cml_word16ToBytes cipherSuite ++
    [legacyCompression] ++
    cml_encodeExtensions extensions
End

(* Representation of a spec serverHello record as the CakeML 6-tuple. *)
Definition reprServerHello_def:
  reprServerHello (sh : serverHello) =
    (w2n sh.legacyVersion, s2ns sh.random, s2ns sh.legacySessionId,
     w2n sh.cipherSuite, w2n sh.legacyCompression, MAP reprExt sh.extensions)
End

Theorem cml_encodeServerHello_refines:
  !sh. wfServerHello sh ==>
       cml_encodeServerHello (reprServerHello sh) = s2ns (encodeServerHello sh)
Proof
  rw[wfServerHello_def] >>
  simp[cml_encodeServerHello_def, reprServerHello_def, encodeServerHello_def] >>
  simp[s2ns_def] >>
  simp[GSYM s2ns_def, cml_word16ToBytes_refines, cml_encodeExtensions_refines] >>
  simp[s2ns_def] >>
  `(LENGTH sh.legacySessionId) MOD 256 = LENGTH sh.legacySessionId`
    by simp[LESS_MOD] >>
  `(n2w (LENGTH sh.legacySessionId) : word8) = n2w (LENGTH sh.legacySessionId MOD 256)`
    by simp[n2w_mod256] >>
  simp[w2n_n2w] >>
  `dimword (:8) = 256` by EVAL_TAC >> simp[]
QED

(* -------------------------------------------------------------------------- *)
(*  ClientHello encode (cakeml/tls.sml: encodeClientHello)                     *)
(* -------------------------------------------------------------------------- *)

(* Hand-mirror of CakeML `encodeClientHello (legacyVersion, random,
   legacySessionId, cipherSuites, legacyCompression, extensions)`.  cipherSuites
   is a CakeML int list (word16 list), legacyCompression is a CakeML int list
   (word8 list), the rest as in encodeServerHello. *)
Definition cml_encodeClientHello_def:
  cml_encodeClientHello ((legacyVersion, random, legacySessionId,
                          cipherSuites, legacyCompression, extensions)
                         : num # num list # num list # num list #
                           num list # (num # num list) list) : num list =
    cml_word16ToBytes legacyVersion ++
    random ++
    (LENGTH legacySessionId :: legacySessionId) ++
    cml_encodeWord16List cipherSuites ++
    (LENGTH legacyCompression :: legacyCompression) ++
    cml_encodeExtensions extensions
End

(* Representation of a spec clientHello record as the CakeML 6-tuple. *)
Definition reprClientHello_def:
  reprClientHello (ch : clientHello) =
    (w2n ch.legacyVersion, s2ns ch.random, s2ns ch.legacySessionId,
     MAP w2n ch.cipherSuites, s2ns ch.legacyCompression, MAP reprExt ch.extensions)
End

Theorem cml_encodeClientHello_refines:
  !ch. wfClientHello ch ==>
       cml_encodeClientHello (reprClientHello ch) = s2ns (encodeClientHello ch)
Proof
  rw[wfClientHello_def] >>
  simp[cml_encodeClientHello_def, reprClientHello_def, encodeClientHello_def] >>
  `2 * LENGTH ch.cipherSuites < 65536` by simp[] >>
  simp[s2ns_def] >>
  simp[GSYM s2ns_def, cml_word16ToBytes_refines, cml_encodeExtensions_refines,
       cml_encodeWord16List_refines] >>
  simp[s2ns_def] >>
  `(LENGTH ch.legacySessionId) MOD 256 = LENGTH ch.legacySessionId` by simp[LESS_MOD] >>
  `(LENGTH ch.legacyCompression) MOD 256 = LENGTH ch.legacyCompression`
    by simp[LESS_MOD] >>
  `(n2w (LENGTH ch.legacySessionId) : word8) =
     n2w (LENGTH ch.legacySessionId MOD 256)` by simp[n2w_mod256] >>
  `(n2w (LENGTH ch.legacyCompression) : word8) =
     n2w (LENGTH ch.legacyCompression MOD 256)` by simp[n2w_mod256] >>
  simp[w2n_n2w] >>
  `dimword (:8) = 256` by EVAL_TAC >> simp[]
QED

(* -------------------------------------------------------------------------- *)
(*  NewSessionTicket encode (cakeml/tls.sml: encodeNewSessionTicket)           *)
(* -------------------------------------------------------------------------- *)

(* Hand-mirror of CakeML `encodeNewSessionTicket (ticketLifetime, ticketAgeAdd,
   ticketNonce, ticket, extensions)`.  ticketLifetime/ticketAgeAdd are CakeML
   ints (word32); ticketNonce/ticket are CakeML strings (num lists). *)
Definition cml_encodeNewSessionTicket_def:
  cml_encodeNewSessionTicket ((ticketLifetime, ticketAgeAdd, ticketNonce,
                               ticket, extensions)
                              : num # num # num list # num list #
                                (num # num list) list) : num list =
    cml_word32ToBytes ticketLifetime ++
    cml_word32ToBytes ticketAgeAdd ++
    (LENGTH ticketNonce :: ticketNonce) ++
    cml_len3 (LENGTH ticket) ++ ticket ++
    cml_encodeExtensions extensions
End

(* Representation of a spec newSessionTicket record as the CakeML 5-tuple. *)
Definition reprNewSessionTicket_def:
  reprNewSessionTicket (t : newSessionTicket) =
    (w2n t.ticketLifetime, w2n t.ticketAgeAdd, s2ns t.ticketNonce,
     s2ns t.ticket, MAP reprExt t.extensions)
End

Theorem cml_encodeNewSessionTicket_refines:
  !t. wfNewSessionTicket t ==>
      cml_encodeNewSessionTicket (reprNewSessionTicket t) =
      s2ns (encodeNewSessionTicket t)
Proof
  rw[wfNewSessionTicket_def] >>
  simp[cml_encodeNewSessionTicket_def, reprNewSessionTicket_def,
       encodeNewSessionTicket_def, encodeOpaque8_def] >>
  simp[s2ns_def] >>
  simp[GSYM s2ns_def, cml_word32ToBytes_refines, cml_encodeExtensions_refines,
       cml_len3_refines] >>
  simp[s2ns_def] >>
  `(LENGTH t.ticketNonce) MOD 256 = LENGTH t.ticketNonce` by simp[LESS_MOD] >>
  `(n2w (LENGTH t.ticketNonce) : word8) = n2w (LENGTH t.ticketNonce MOD 256)`
    by simp[n2w_mod256] >>
  simp[w2n_n2w] >>
  `dimword (:8) = 256` by EVAL_TAC >> simp[]
QED

(* -------------------------------------------------------------------------- *)
(*  Certificate encode (cakeml/tls.sml: encodeCertificate)                     *)
(* -------------------------------------------------------------------------- *)

(* Hand-mirror of CakeML `oneEntry (certData, extensions)`:
     len3 (size certData) ^ certData ^ encodeExtensions extensions. *)
Definition cml_encodeCertEntry_def:
  cml_encodeCertEntry ((certData, extensions) : num list # (num # num list) list)
      : num list =
    cml_len3 (LENGTH certData) ++ certData ++ cml_encodeExtensions extensions
End

Definition cml_encodeCertEntries_def:
  cml_encodeCertEntries (es : (num list # (num # num list) list) list) : num list =
    FLAT (MAP cml_encodeCertEntry es)
End

(* Hand-mirror of CakeML `encodeCertificate (certificateRequestContext,
   certificateList)`:
     (chr (ctxLen mod 256) ^ ctx) ^ len3 entriesLen ^ entries. *)
Definition cml_encodeCertificate_def:
  cml_encodeCertificate ((certificateRequestContext, certificateList)
                         : num list # (num list # (num # num list) list) list)
      : num list =
    (LENGTH certificateRequestContext MOD 256 :: certificateRequestContext) ++
    (let entries = cml_encodeCertEntries certificateList in
       cml_len3 (LENGTH entries) ++ entries)
End

(* Representation of a spec certificateEntry / certificate as CakeML tuples. *)
Definition reprCertEntry_def:
  reprCertEntry (e : certificateEntry) =
    (s2ns e.certData, MAP reprExt e.extensions)
End

Definition reprCertificate_def:
  reprCertificate (c : certificate) =
    (s2ns c.certificateRequestContext, MAP reprCertEntry c.certificateList)
End

(* The per-entry encoder refines, given each entry's certData fits the 3-byte
   length field and its extensions fit the 2-byte fields. *)
Theorem cml_encodeCertEntry_refines:
  !e. LENGTH e.certData < 16777216 /\
      EVERY (\x. LENGTH x.data < 65536) e.extensions /\
      LENGTH (FLAT (MAP encodeExtension e.extensions)) < 65536 ==>
      cml_encodeCertEntry (reprCertEntry e) = s2ns (encodeCertEntry e)
Proof
  rw[reprCertEntry_def, cml_encodeCertEntry_def, encodeCertEntry_def] >>
  simp[s2ns_def] >>
  simp[GSYM s2ns_def, cml_len3_refines, cml_encodeExtensions_refines] >>
  simp[s2ns_def]
QED

(* The entries-block encoder refines (concatenation of per-entry encodings). *)
Theorem cml_encodeCertEntries_refines:
  !es. EVERY (\e. LENGTH e.certData < 16777216 /\
                  EVERY (\x. LENGTH x.data < 65536) e.extensions /\
                  LENGTH (FLAT (MAP encodeExtension e.extensions)) < 65536) es ==>
       cml_encodeCertEntries (MAP reprCertEntry es) =
       s2ns (encodeCertEntries es)
Proof
  simp[cml_encodeCertEntries_def, encodeCertEntries_def] >>
  Induct >> simp[s2ns_def] >>
  rpt strip_tac >> fs[] >>
  `cml_encodeCertEntry (reprCertEntry h) = s2ns (encodeCertEntry h)`
    by simp[cml_encodeCertEntry_refines] >>
  simp[s2ns_def]
QED

(* The certificate length-prefix invariant: the CakeML entries block has the
   same length as the spec entries block (they are proved equal). *)
Theorem cml_encodeCertificate_refines:
  !c. wfCertificate c ==>
      cml_encodeCertificate (reprCertificate c) = s2ns (encodeCertificate c)
Proof
  rw[wfCertificate_def] >>
  simp[cml_encodeCertificate_def, reprCertificate_def, encodeCertificate_def,
       encodeOpaque8_def] >>
  `cml_encodeCertEntries (MAP reprCertEntry c.certificateList) =
     s2ns (encodeCertEntries c.certificateList)`
    by simp[cml_encodeCertEntries_refines] >>
  `LENGTH (cml_encodeCertEntries (MAP reprCertEntry c.certificateList)) =
     LENGTH (encodeCertEntries c.certificateList)`
    by (pop_assum (fn th => REWRITE_TAC[th]) >> simp[s2ns_def]) >>
  ntac 2 (pop_assum mp_tac) >> rw[] >>
  simp[s2ns_def] >>
  simp[GSYM s2ns_def, cml_len3_refines] >>
  simp[s2ns_def] >>
  `(LENGTH c.certificateRequestContext) MOD 256 =
     LENGTH c.certificateRequestContext` by simp[LESS_MOD] >>
  `(n2w (LENGTH c.certificateRequestContext) : word8) =
     n2w (LENGTH c.certificateRequestContext MOD 256)` by simp[n2w_mod256] >>
  simp[w2n_n2w] >>
  `dimword (:8) = 256` by EVAL_TAC >> simp[]
QED

(* -------------------------------------------------------------------------- *)
(*  Encode/decode composition: the CakeML wire bytes round-trip via the spec  *)
(*                                                                            *)
(*  Each `cml_encode<X>` refinement above proves the CakeML port emits EXACTLY *)
(*  the spec encoder's byte string (transported through s2ns).  Composing with *)
(*  the Track 2a round-trips `decode_encode_<X>` gives a single sound          *)
(*  statement per codec: there is a spec byte string `bs` (namely encode<X> r) *)
(*  such that the CakeML encoder output is `s2ns bs` AND the spec decoder      *)
(*  recovers `r` from `bs`.  Since `s2ns = MAP w2n` is injective on byte       *)
(*  lists, this pins the CakeML encoder output to a wire string the spec       *)
(*  decoder inverts --- the encode side of a full CakeML<->spec round trip.    *)
(* -------------------------------------------------------------------------- *)

Theorem cml_serverHello_roundtrip_via_spec:
  !sh. wfServerHello sh ==>
       ?bs. cml_encodeServerHello (reprServerHello sh) = s2ns bs /\
            decodeServerHello bs = SOME sh
Proof
  rw[] >> qexists_tac `encodeServerHello sh` >>
  simp[cml_encodeServerHello_refines, decode_encode_serverHello]
QED

Theorem cml_clientHello_roundtrip_via_spec:
  !ch. wfClientHello ch ==>
       ?bs. cml_encodeClientHello (reprClientHello ch) = s2ns bs /\
            decodeClientHello bs = SOME ch
Proof
  rw[] >> qexists_tac `encodeClientHello ch` >>
  simp[cml_encodeClientHello_refines, decode_encode_clientHello]
QED

Theorem cml_newSessionTicket_roundtrip_via_spec:
  !t. wfNewSessionTicket t ==>
      ?bs. cml_encodeNewSessionTicket (reprNewSessionTicket t) = s2ns bs /\
           decodeNewSessionTicket bs = SOME t
Proof
  rw[] >> qexists_tac `encodeNewSessionTicket t` >>
  simp[cml_encodeNewSessionTicket_refines, decode_encode_newSessionTicket]
QED

Theorem cml_certificate_roundtrip_via_spec:
  !c. wfCertificate c ==>
      ?bs. cml_encodeCertificate (reprCertificate c) = s2ns bs /\
           decodeCertificate bs = SOME c
Proof
  rw[] >> qexists_tac `encodeCertificate c` >>
  simp[cml_encodeCertificate_refines, decode_encode_certificate]
QED

(* -------------------------------------------------------------------------- *)
(*  State-machine refinement (PARTIAL): CakeML TlsClient.step control phase   *)
(*  vs the abstract tls_handshakeTheory client automaton.                      *)
(* -------------------------------------------------------------------------- *)

(* SCOPE / HONESTY.  The full CakeML `TlsClient.step` (cakeml/tls_state.sml) is
   an exception-driven, crypto-bearing byte processor: it decrypts flights,
   runs X25519 / AEAD / the key schedule, parses every handshake message, and
   threads a 15-field state tuple.  The tls_handshakeTheory automaton is, by
   contrast, an ABSTRACT event-labeled FSM with no message contents and no
   keys.  A full simulation between the two requires modeling the entire crypto
   stack and is the "months, not weeks" frontier work flagged for Track 2d.

   What is genuinely tractable here is the CONTROL-PHASE abstraction: the
   dispatcher at the top of `TlsClient.step` selects its behaviour purely from
   three control flags of the state tuple --- `errorAlert` (set?),
   `cipherSuiteOpt` (set?), and `connected`.  We model exactly those three
   flags and prove that the client state built by `TlsClient.startHandshake`
   abstracts to the abstract automaton's post-`SendClientHello` state, i.e. the
   first handshake transition is faithfully refined.

   This is a real, sound refinement of ONE transition (the ClientHello send);
   it is NOT a full simulation.  The remaining transitions depend on the crypto
   stack and are Track 2d. *)

(* The three control flags the CakeML `step` dispatcher branches on, as a
   faithful projection of the 15-field client-state tuple
   (errorAlert = field 14, cipherSuiteOpt = field 5, connected = field 15). *)
Datatype:
  cmlClientCtrl =
    <| errSet  : bool;     (* errorAlert is (Some _) *)
       csSet   : bool;     (* cipherSuiteOpt is (Some _) *)
       conn    : bool |>   (* connected flag *)
End

(* Abstraction of the CakeML control flags to the abstract automaton's
   client phase.  Mirrors the dispatch in `TlsClient.step`:
     - errorAlert set      -> the connection is being torn down (CClosed);
     - no cipher suite yet  -> still waiting to process ServerHello, i.e. the
       ClientHello has been sent (CClientHelloSent);
     - cipher suite, not connected -> mid handshake, server flight pending
       (CServerHelloReceived is the representative pre-Finished phase);
     - connected            -> CConnected. *)
Definition cmlClientAbs_def:
  cmlClientAbs (c : cmlClientCtrl) : clientState =
    if c.errSet then CClosed
    else if c.conn then CConnected
    else if c.csSet then CServerHelloReceived
    else CClientHelloSent
End

(* The control flags of the state produced by `TlsClient.startHandshake`:
   it sets errorAlert = None, cipherSuiteOpt = None, connected = False
   (see cakeml/tls_state.sml `startHandshake`: the state tuple is
     (cfg, priv, ch, msg, None, "", None, ..., False, None, False)
   so csSet = F, errSet = F, conn = F). *)
Definition cmlStartHandshakeCtrl_def:
  cmlStartHandshakeCtrl : cmlClientCtrl =
    <| errSet := F; csSet := F; conn := F |>
End

(* REFINEMENT (one transition).  The CakeML client state right after
   `startHandshake` abstracts to exactly the abstract automaton's state after
   the legal `SendClientHello` transition out of `CIdle`. *)
Theorem cml_startHandshake_refines_transition:
  client_transition CIdle SendClientHello = SOME (cmlClientAbs cmlStartHandshakeCtrl)
Proof
  rw[client_transition_def, cmlClientAbs_def, cmlStartHandshakeCtrl_def]
QED

(* The dispatcher's error branch (`case errA of Some _ => (st, [])` then
   alert/teardown) is faithfully abstracted: any CakeML client whose
   errorAlert flag is set abstracts to the abstract automaton's CClosed state,
   matching `client_transition _ SendCloseNotify = SOME CClosed`. *)
Theorem cml_errored_abs_closed:
  !c. c.errSet ==> cmlClientAbs c = CClosed
Proof
  rw[cmlClientAbs_def]
QED

Theorem cml_closed_refines_transition:
  !c s. c.errSet ==>
        client_transition s SendCloseNotify = SOME (cmlClientAbs c)
Proof
  rw[cml_errored_abs_closed, client_transition_def]
QED

(* The dispatcher's connected branch (`if not conn then ... else (st, [])`)
   is faithfully abstracted: a non-errored, connected CakeML client abstracts
   to CConnected, on which the abstract automaton idles under application
   data, matching `client_transition CConnected SendApplicationData =
   SOME CConnected`. *)
Theorem cml_connected_abs:
  !c. ~c.errSet /\ c.conn ==> cmlClientAbs c = CConnected
Proof
  rw[cmlClientAbs_def]
QED

Theorem cml_connected_refines_idle:
  !c. ~c.errSet /\ c.conn ==>
      client_transition (cmlClientAbs c) SendApplicationData = SOME (cmlClientAbs c)
Proof
  rw[cml_connected_abs, client_transition_def]
QED

val _ = export_theory ();