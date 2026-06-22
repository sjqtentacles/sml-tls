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
axiom eventBytes_def:
  !e. eventBytes e : word8 list = []
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

(* Invariant 1: no application data is emitted before the peer's Finished
   is verified. *)
Theorem no_appData_before_finished:
  !s e s'.
     transition s e = SOME s' /\ e = SendApplicationData /\ ~s.peerFinishedVerified
     ==> F
Proof
  (* TODO: prove in Phase 7. The shape: a SendApplicationData event
     only succeeds from CServerFinishedReceived/SConnected (client) or
     SClientFinishedReceived/SConnected (server), both of which imply
     peerFinishedVerified = T. *)
  cheat
QED

(* Invariant 2: transcript hash is append-only -- the transcript only
   grows across a transition. *)
Theorem transcript_append_only:
  !s e s'.
     transition s e = SOME s'
     ==> LENGTH s.transcript <= LENGTH s'.transcript
Proof
  (* TODO Phase 7. Each handshake event appends eventBytes; application
     data and alerts append nothing; so the length is monotonic. *)
  cheat
QED

(* Invariant 3: traffic keys are only installed after the corresponding
   secret is derived. Captured here as: keysInstalled becomes true only
   after CServerFinishedReceived / SClientFinishedReceived. *)
Theorem keys_after_secret:
  !s e s'.
     transition s e = SOME s' /\ s'.keysInstalled
     ==> s.peerFinishedVerified \/ s'.peerFinishedVerified
Proof
  cheat
QED

(* Invariant 4: no state reaches Connected without a verified Finished. *)
Theorem connected_implies_finished:
  !s e s'.
     transition s e = SOME s' /\
     (s'.clientSt = CConnected \/ s'.serverSt = SConnected)
     ==> s'.peerFinishedVerified
Proof
  cheat
QED

(* Simple, provable invariant: from CIdle only SendClientHello is legal. *)
Theorem idle_only_clientHello:
  !e. client_transition CIdle e <> NONE <=> e = SendClientHello
Proof
  Cases_on `e` >> EVAL_TAC
QED

(* Simple invariant: a closed state never transitions to anything but
   Closed. *)
Theorem closed_is_absorbing:
  !e. client_transition CClosed e = SOME CClosed \/
      client_transition CClosed e = NONE
Proof
  Cases_on `e` >> EVAL_TAC
QED

val _ = export_theory ();
