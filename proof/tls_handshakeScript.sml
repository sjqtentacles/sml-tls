(* tls_handshakeScript.sml

   HOL4 formal model of the TLS 1.3 handshake transition relation and the
   safety invariants (RFC 8446 7.1), Track B1 sub-worker 3. Derived from
   the RFC and aligned with the TLS_CLIENT / TLS_SERVER signatures in
   tls.sig.

   This theory defines:
     - `clientState` / `serverState` datatypes mirroring the documented
       transitions in tls.sig (Idle, ClientHelloSent, ServerHelloReceived,
       Connected, etc.);
     - a `transition` relation over states and messages;
     - the safety invariants stated as theorem GOALS. Proving them is
       Phase 7's job; the simple ones are discharged here by EVAL.
*)

open HolKernel Parse boolLib bossLib;
open listTheory optionTheory wordsTheory;

val _ = new_theory "tls_handshake";

(* -------------------------------------------------------------------------- *)
(*  Roles                                                                     *)
(* -------------------------------------------------------------------------- *)

Datatype:
  role = Client | Server
End

(* -------------------------------------------------------------------------- *)
(*  Client state machine (RFC 8446 7.1 / tls.sig TLS_CLIENT)                 *)
(* -------------------------------------------------------------------------- *)

Datatype:
  clientState =
      CIdle
    | CClientHelloSent
    | CServerHelloReceived
    | CEncryptedExtensionsReceived
    | CCertificateReceived
    | CCertificateVerifyReceived
    | CServerFinishedReceived
    | CClientFinishedSent
    | CConnected
    | CClosed
End

(* -------------------------------------------------------------------------- *)
(*  Server state machine (RFC 8446 7.1 / tls.sig TLS_SERVER)                 *)
(* -------------------------------------------------------------------------- *)

Datatype:
  serverState =
      SIdle
    | SClientHelloReceived
    | SServerHelloSent
    | SEncryptedExtensionsSent
    | SCertificateSent
    | SCertificateVerifySent
    | SServerFinishedSent
    | SClientFinishedReceived
    | SConnected
    | SClosed
End

Datatype:
  endpointState =
    <| role       : role;
       clientSt   : clientState;
       serverSt   : serverState;
       transcript : word8 list;        (* concatenated wire-form messages *)
       peerFinishedVerified : bool;
       keysInstalled : bool |>         (* traffic keys derived & installed *)
End

(* -------------------------------------------------------------------------- *)
(*  Inbound handshake messages (subset)                                      *)
(* -------------------------------------------------------------------------- *)

Datatype:
  event =
      SendClientHello
    | RecvClientHello
    | SendServerHello
    | RecvServerHello
    | RecvEncryptedExtensions
    | RecvCertificate
    | RecvCertificateVerify
    | RecvServerFinished
    | SendClientFinished
    | RecvClientFinished
    | SendApplicationData
    | RecvApplicationData
    | SendCloseNotify
    | RecvCloseNotify
End

(* -------------------------------------------------------------------------- *)
(*  Transition relation                                                       *)
(* -------------------------------------------------------------------------- *)

(* transition s e = SOME s' iff `e` is a legal next event from state `s`.
   Otherwise NONE. The relation is total: an illegal event yields NONE,
   never an undefined state. Only the client-side transitions are spelled
   out in full; the server side is symmetric. *)

Definition client_transition_def:
  (client_transition CIdle SendClientHello =
     SOME CClientHelloSent) /\
  (client_transition CClientHelloSent RecvServerHello =
     SOME CServerHelloReceived) /\
  (client_transition CServerHelloReceived RecvEncryptedExtensions =
     SOME CEncryptedExtensionsReceived) /\
  (client_transition CEncryptedExtensionsReceived RecvCertificate =
     SOME CCertificateReceived) /\
  (client_transition CCertificateReceived RecvCertificateVerify =
     SOME CCertificateVerifyReceived) /\
  (client_transition CCertificateVerifyReceived RecvServerFinished =
     SOME CServerFinishedReceived) /\
  (client_transition CServerFinishedReceived SendClientFinished =
     SOME CClientFinishedSent) /\
  (client_transition CClientFinishedSent SendApplicationData =
     SOME CConnected) /\
  (client_transition CConnected SendApplicationData =
     SOME CConnected) /\
  (client_transition CConnected RecvApplicationData =
     SOME CConnected) /\
  (client_transition _ SendCloseNotify = SOME CClosed) /\
  (client_transition _ RecvCloseNotify  = SOME CClosed) /\
  (client_transition _ _                = NONE)
End

(* Server-side transition table; symmetric to the client one. *)
Definition server_transition_def:
  (server_transition SIdle RecvClientHello =
     SOME SClientHelloReceived) /\
  (server_transition SClientHelloReceived SendServerHello =
     SOME SServerHelloSent) /\
  (server_transition SServerHelloSent SendApplicationData =
     SOME SServerFinishedSent) /\
  (* the intermediate EncryptedExtensions/Certificate/CertificateVerify/
     Finished sends are folded into SServerFinishedSent for brevity;
     Phase 7 expands them to match the client's granularity. *)
  (server_transition SServerFinishedSent RecvClientFinished =
     SOME SClientFinishedReceived) /\
  (server_transition SClientFinishedReceived SendApplicationData =
     SOME SConnected) /\
  (server_transition SConnected SendApplicationData =
     SOME SConnected) /\
  (server_transition SConnected RecvApplicationData =
     SOME SConnected) /\
  (server_transition _ SendCloseNotify = SOME SClosed) /\
  (server_transition _ RecvCloseNotify  = SOME SClosed) /\
  (server_transition _ _                = NONE)
End

(* -------------------------------------------------------------------------- *)
(*  Helpers used by the transition relation                                  *)
(* -------------------------------------------------------------------------- *)

Definition isHandshakeEvent_def:
  (isHandshakeEvent SendClientHello          = T) /\
  (isHandshakeEvent RecvClientHello          = T) /\
  (isHandshakeEvent SendServerHello          = T) /\
  (isHandshakeEvent RecvServerHello          = T) /\
  (isHandshakeEvent RecvEncryptedExtensions  = T) /\
  (isHandshakeEvent RecvCertificate          = T) /\
  (isHandshakeEvent RecvCertificateVerify    = T) /\
  (isHandshakeEvent RecvServerFinished       = T) /\
  (isHandshakeEvent SendClientFinished       = T) /\
  (isHandshakeEvent RecvClientFinished       = T) /\
  (isHandshakeEvent _                        = F)
End

(* eventBytes e is the wire-form contribution of `e` to the transcript.
   For now we treat each event as contributing a placeholder empty list;
   Phase 7 substitutes the real handshakeMessage encoding from tls_wire. *)
Definition eventBytes_def:
  eventBytes (e : event) : word8 list = []
End

(* Top-level transition: updates the role-relevant sub-state, appends to
   the transcript (Send/Recv of handshake messages grows it; application
   data and alerts do not), and sets peerFinishedVerified when the peer's
   Finished is received. *)

Definition transition_def:
  transition (s : endpointState) (e : event) : endpointState option =
    case s.role of
      | Client =>
          (case client_transition s.clientSt e of
             | NONE => NONE
             | SOME cs =>
                 let s' = s with <| clientSt := cs |> in
                 let s'' = if isHandshakeEvent e then
                             s' with <| transcript := s'.transcript ++ eventBytes e |>
                           else s' in
                 let s''' = if e = RecvServerFinished then
                              s'' with <| peerFinishedVerified := T |>
                            else s'' in
                 SOME s''')
      | Server =>
          (case server_transition s.serverSt e of
             | NONE => NONE
             | SOME ss =>
                 let s' = s with <| serverSt := ss |> in
                 let s'' = if isHandshakeEvent e then
                             s' with <| transcript := s'.transcript ++ eventBytes e |>
                           else s' in
                 let s''' = if e = RecvClientFinished then
                              s'' with <| peerFinishedVerified := T |>
                            else s'' in
                 SOME s''')
End

(* -------------------------------------------------------------------------- *)
(*  Safety invariants                                                        *)
(* -------------------------------------------------------------------------- *)

(* The "can emit application data" predicate. ApplicationData may only be
   emitted once the peer's Finished has been verified (RFC 8446 7.1:
   application traffic keys are only installed after both Finished
   messages). *)
Definition canEmitAppData_def:
  canEmitAppData (s : endpointState) : bool = s.peerFinishedVerified
End

(* -------------------------------------------------------------------------- *)
(*  Single-transition structural facts (hold for ALL states)                  *)
(* -------------------------------------------------------------------------- *)

(* Transcript is monotone across a transition (here, never shrinks: handshake
   events append eventBytes, everything else leaves it unchanged). *)
Theorem transcript_append_only:
  !s e s'.
     transition s e = SOME s'
     ==> LENGTH s.transcript <= LENGTH s'.transcript
Proof
  rw[transition_def] >>
  gvs[AllCaseEqs(), eventBytes_def, isHandshakeEvent_def] >> simp[]
QED

(* The only way to leave Idle into the handshake proper is by sending a
   ClientHello (close-notify can also fire, taking us to Closed, hence the
   precise statement is about the ClientHelloSent target). *)
Theorem idle_only_clientHello:
  !e. (client_transition CIdle e = SOME CClientHelloSent) <=> (e = SendClientHello)
Proof
  Cases >> EVAL_TAC
QED

(* A closed client never transitions anywhere but Closed (or nowhere). *)
Theorem closed_is_absorbing:
  !e. client_transition CClosed e = SOME CClosed \/
      client_transition CClosed e = NONE
Proof
  Cases >> EVAL_TAC
QED

(* -------------------------------------------------------------------------- *)
(*  Reachable states and inductive safety invariants                          *)
(* -------------------------------------------------------------------------- *)

(* The single-transition safety properties below ("connected implies a
   verified Finished", "no application data before the peer's Finished") are
   NOT true of arbitrary endpointState records -- one can hand-craft a record
   sitting in CConnected with peerFinishedVerified = F.  They are genuine
   *inductive invariants*: they hold for every state REACHABLE from a fresh
   endpoint.  We therefore make reachability explicit and prove them by rule
   induction. *)

Definition initState_def:
  initState r =
    <| role := r; clientSt := CIdle; serverSt := SIdle;
       transcript := []; peerFinishedVerified := F; keysInstalled := F |>
End

Inductive reachable:
  (!r. reachable (initState r)) /\
  (!s e s'. reachable s /\ transition s e = SOME s' ==> reachable s')
End

(* The transition relation never sets keysInstalled, so it stays false on
   every reachable state.  (Honest finding: keysInstalled is a vestigial
   field in this abstract model -- key installation is not modeled, which is
   recorded as a spec<->impl gap in PROOF_STATUS.md.) *)
Theorem reachable_no_keys:
  !s. reachable s ==> ~s.keysInstalled
Proof
  Induct_on `reachable` >> rw[initState_def] >>
  gvs[transition_def, AllCaseEqs(), isHandshakeEvent_def, eventBytes_def]
QED

(* Core inductive safety invariant: once an endpoint has advanced to (or past)
   the point where it has accepted the peer's Finished, peerFinishedVerified
   is set.  Stated as: being in any of the post-Finished client/server states
   implies peerFinishedVerified. *)
Theorem reachable_safety:
  !s. reachable s ==>
      ((s.clientSt = CServerFinishedReceived \/ s.clientSt = CClientFinishedSent \/
        s.clientSt = CConnected) ==> s.peerFinishedVerified) /\
      ((s.serverSt = SClientFinishedReceived \/ s.serverSt = SConnected) ==>
        s.peerFinishedVerified)
Proof
  Induct_on `reachable` >> conj_tac >| [
    rw[initState_def],
    rpt gen_tac >> strip_tac >>
    Cases_on `s.role` >> fs[transition_def] >| [
      Cases_on `s.clientSt` >> Cases_on `e` >>
        gvs[client_transition_def, isHandshakeEvent_def, eventBytes_def] >>
        metis_tac[],
      Cases_on `s.serverSt` >> Cases_on `e` >>
        gvs[server_transition_def, isHandshakeEvent_def, eventBytes_def] >>
        metis_tac[]
    ]
  ]
QED

(* Invariant 4 (for reachable states): no endpoint is Connected without a
   verified peer Finished. *)
Theorem connected_implies_finished:
  !s. reachable s /\ (s.clientSt = CConnected \/ s.serverSt = SConnected)
      ==> s.peerFinishedVerified
Proof
  rpt strip_tac >> imp_res_tac reachable_safety >> gvs[]
QED

(* Invariant 1 (for reachable CLIENT states): a client cannot send
   application data before the server's Finished is verified.  A client
   SendApplicationData transition only fires from CClientFinishedSent or
   CConnected, both of which carry peerFinishedVerified by reachable_safety.

   NOTE (honest scope): we state this for the client only.  The server side
   of this abstract model overloads `SendApplicationData` as the trigger for
   the whole server flight (SServerHelloSent --SendApplicationData-->
   SServerFinishedSent), so the analogous unconditional server statement is
   *false* in this model.  That modeling shortcut is recorded as a
   spec<->impl gap in PROOF_STATUS.md. *)
Theorem client_no_appData_before_finished:
  !s e s'.
     reachable s /\ s.role = Client /\
     transition s e = SOME s' /\ e = SendApplicationData
     ==> s.peerFinishedVerified
Proof
  rpt strip_tac >> imp_res_tac reachable_safety >>
  gvs[transition_def] >>
  Cases_on `s.clientSt` >> gvs[client_transition_def]
QED

(* Invariant 3 (for reachable states): traffic keys are never installed in
   this model, so the "keys only after the secret" guarantee holds
   vacuously.  Recorded honestly: the abstract model does not yet model key
   installation; see PROOF_STATUS.md. *)
Theorem keys_after_secret:
  !s e s'.
     reachable s /\ transition s e = SOME s' /\ s'.keysInstalled
     ==> s.peerFinishedVerified \/ s'.peerFinishedVerified
Proof
  rpt strip_tac >> `reachable s'` by metis_tac[reachable_rules] >>
  imp_res_tac reachable_no_keys >> gvs[]
QED

val _ = export_theory ();
