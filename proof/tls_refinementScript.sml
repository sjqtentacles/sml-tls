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