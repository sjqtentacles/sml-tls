structure tls_handshakeTheory :> tls_handshakeTheory =
struct
  
  val _ = if !Globals.print_thy_loads
    then TextIO.print "Loading tls_handshakeTheory ... "
    else ()
  
  open Type Term Thm
  local open wordsTheory EnumType in end;
  
  structure TDB = struct
    val path =
      OS.Path.base (#(FILE)) ^ ".dat"
    val timestamp = HOLFileSys.modTime path
    val thydata = 
      TheoryReader.load_thydata {
        thyname = "tls_handshake",
        hash = "6dda88e4e00cb6e5cf3266a1205d83d47d55e86c",
        path = path
      }
    fun find s = #1 (valOf (Symtab.lookup thydata s))
  end
  val () = Theory.record_metadata
    "tls_handshake" {timestamp=TDB.timestamp, path=TDB.path}
  
  fun op transition_def _ = ()
  val op transition_def = TDB.find "transition_def"
  fun op transcript_append_only _ = ()
  val op transcript_append_only = TDB.find "transcript_append_only"
  fun op server_transition_ind _ = ()
  val op server_transition_ind = TDB.find "server_transition_ind"
  fun op server_transition_def _ = ()
  val op server_transition_def = TDB.find "server_transition_def"
  fun op serverState_size_def _ = ()
  val op serverState_size_def = TDB.find "serverState_size_def"
  fun op serverState_nchotomy _ = ()
  val op serverState_nchotomy = TDB.find "serverState_nchotomy"
  fun op serverState_induction _ = ()
  val op serverState_induction = TDB.find "serverState_induction"
  fun op serverState_distinct _ = ()
  val op serverState_distinct = TDB.find "serverState_distinct"
  fun op serverState_case_eq _ = ()
  val op serverState_case_eq = TDB.find "serverState_case_eq"
  fun op serverState_case_def _ = ()
  val op serverState_case_def = TDB.find "serverState_case_def"
  fun op serverState_case_cong _ = ()
  val op serverState_case_cong = TDB.find "serverState_case_cong"
  fun op serverState_TY_DEF _ = ()
  val op serverState_TY_DEF = TDB.find "serverState_TY_DEF"
  fun op serverState_EQ_serverState _ = ()
  val op serverState_EQ_serverState = TDB.find "serverState_EQ_serverState"
  fun op serverState_CASE _ = ()
  val op serverState_CASE = TDB.find "serverState_CASE"
  fun op serverState_BIJ _ = ()
  val op serverState_BIJ = TDB.find "serverState_BIJ"
  fun op serverState_Axiom _ = ()
  val op serverState_Axiom = TDB.find "serverState_Axiom"
  fun op serverState2num_thm _ = ()
  val op serverState2num_thm = TDB.find "serverState2num_thm"
  fun op serverState2num_num2serverState _ = ()
  val op serverState2num_num2serverState = TDB.find
    "serverState2num_num2serverState"
  fun op serverState2num_ONTO _ = ()
  val op serverState2num_ONTO = TDB.find "serverState2num_ONTO"
  fun op serverState2num_11 _ = ()
  val op serverState2num_11 = TDB.find "serverState2num_11"
  fun op role_size_def _ = ()
  val op role_size_def = TDB.find "role_size_def"
  fun op role_nchotomy _ = ()
  val op role_nchotomy = TDB.find "role_nchotomy"
  fun op role_induction _ = ()
  val op role_induction = TDB.find "role_induction"
  fun op role_distinct _ = ()
  val op role_distinct = TDB.find "role_distinct"
  fun op role_case_eq _ = () val op role_case_eq = TDB.find "role_case_eq"
  fun op role_case_def _ = ()
  val op role_case_def = TDB.find "role_case_def"
  fun op role_case_cong _ = ()
  val op role_case_cong = TDB.find "role_case_cong"
  fun op role_TY_DEF _ = () val op role_TY_DEF = TDB.find "role_TY_DEF"
  fun op role_EQ_role _ = () val op role_EQ_role = TDB.find "role_EQ_role"
  fun op role_CASE _ = () val op role_CASE = TDB.find "role_CASE"
  fun op role_BIJ _ = () val op role_BIJ = TDB.find "role_BIJ"
  fun op role_Axiom _ = () val op role_Axiom = TDB.find "role_Axiom"
  fun op role2num_thm _ = () val op role2num_thm = TDB.find "role2num_thm"
  fun op role2num_num2role _ = ()
  val op role2num_num2role = TDB.find "role2num_num2role"
  fun op role2num_ONTO _ = ()
  val op role2num_ONTO = TDB.find "role2num_ONTO"
  fun op role2num_11 _ = () val op role2num_11 = TDB.find "role2num_11"
  fun op recordtype_endpointState_seldef_transcript_fupd_def _ = ()
  val op recordtype_endpointState_seldef_transcript_fupd_def = TDB.find
    "recordtype_endpointState_seldef_transcript_fupd_def"
  fun op recordtype_endpointState_seldef_transcript_def _ = ()
  val op recordtype_endpointState_seldef_transcript_def = TDB.find
    "recordtype_endpointState_seldef_transcript_def"
  fun op recordtype_endpointState_seldef_serverSt_fupd_def _ = ()
  val op recordtype_endpointState_seldef_serverSt_fupd_def = TDB.find
    "recordtype_endpointState_seldef_serverSt_fupd_def"
  fun op recordtype_endpointState_seldef_serverSt_def _ = ()
  val op recordtype_endpointState_seldef_serverSt_def = TDB.find
    "recordtype_endpointState_seldef_serverSt_def"
  fun op recordtype_endpointState_seldef_role_fupd_def _ = ()
  val op recordtype_endpointState_seldef_role_fupd_def = TDB.find
    "recordtype_endpointState_seldef_role_fupd_def"
  fun op recordtype_endpointState_seldef_role_def _ = ()
  val op recordtype_endpointState_seldef_role_def = TDB.find
    "recordtype_endpointState_seldef_role_def"
  fun op recordtype_endpointState_seldef_peerFinishedVerified_fupd_def _ =
    ()
  val op recordtype_endpointState_seldef_peerFinishedVerified_fupd_def =
    TDB.find
    "recordtype_endpointState_seldef_peerFinishedVerified_fupd_def"
  fun op recordtype_endpointState_seldef_peerFinishedVerified_def _ = ()
  val op recordtype_endpointState_seldef_peerFinishedVerified_def =
    TDB.find "recordtype_endpointState_seldef_peerFinishedVerified_def"
  fun op recordtype_endpointState_seldef_keysInstalled_fupd_def _ = ()
  val op recordtype_endpointState_seldef_keysInstalled_fupd_def = TDB.find
    "recordtype_endpointState_seldef_keysInstalled_fupd_def"
  fun op recordtype_endpointState_seldef_keysInstalled_def _ = ()
  val op recordtype_endpointState_seldef_keysInstalled_def = TDB.find
    "recordtype_endpointState_seldef_keysInstalled_def"
  fun op recordtype_endpointState_seldef_clientSt_fupd_def _ = ()
  val op recordtype_endpointState_seldef_clientSt_fupd_def = TDB.find
    "recordtype_endpointState_seldef_clientSt_fupd_def"
  fun op recordtype_endpointState_seldef_clientSt_def _ = ()
  val op recordtype_endpointState_seldef_clientSt_def = TDB.find
    "recordtype_endpointState_seldef_clientSt_def"
  fun op num2serverState_thm _ = ()
  val op num2serverState_thm = TDB.find "num2serverState_thm"
  fun op num2serverState_serverState2num _ = ()
  val op num2serverState_serverState2num = TDB.find
    "num2serverState_serverState2num"
  fun op num2serverState_ONTO _ = ()
  val op num2serverState_ONTO = TDB.find "num2serverState_ONTO"
  fun op num2serverState_11 _ = ()
  val op num2serverState_11 = TDB.find "num2serverState_11"
  fun op num2role_thm _ = () val op num2role_thm = TDB.find "num2role_thm"
  fun op num2role_role2num _ = ()
  val op num2role_role2num = TDB.find "num2role_role2num"
  fun op num2role_ONTO _ = ()
  val op num2role_ONTO = TDB.find "num2role_ONTO"
  fun op num2role_11 _ = () val op num2role_11 = TDB.find "num2role_11"
  fun op num2event_thm _ = ()
  val op num2event_thm = TDB.find "num2event_thm"
  fun op num2event_event2num _ = ()
  val op num2event_event2num = TDB.find "num2event_event2num"
  fun op num2event_ONTO _ = ()
  val op num2event_ONTO = TDB.find "num2event_ONTO"
  fun op num2event_11 _ = () val op num2event_11 = TDB.find "num2event_11"
  fun op num2clientState_thm _ = ()
  val op num2clientState_thm = TDB.find "num2clientState_thm"
  fun op num2clientState_clientState2num _ = ()
  val op num2clientState_clientState2num = TDB.find
    "num2clientState_clientState2num"
  fun op num2clientState_ONTO _ = ()
  val op num2clientState_ONTO = TDB.find "num2clientState_ONTO"
  fun op num2clientState_11 _ = ()
  val op num2clientState_11 = TDB.find "num2clientState_11"
  fun op no_appData_before_finished _ = ()
  val op no_appData_before_finished = TDB.find "no_appData_before_finished"
  fun op keys_after_secret _ = ()
  val op keys_after_secret = TDB.find "keys_after_secret"
  fun op isHandshakeEvent_ind _ = ()
  val op isHandshakeEvent_ind = TDB.find "isHandshakeEvent_ind"
  fun op isHandshakeEvent_def_primitive _ = ()
  val op isHandshakeEvent_def_primitive = TDB.find
    "isHandshakeEvent_def_primitive"
  fun op isHandshakeEvent_def _ = ()
  val op isHandshakeEvent_def = TDB.find "isHandshakeEvent_def"
  fun op idle_only_clientHello _ = ()
  val op idle_only_clientHello = TDB.find "idle_only_clientHello"
  fun op event_size_def _ = ()
  val op event_size_def = TDB.find "event_size_def"
  fun op event_nchotomy _ = ()
  val op event_nchotomy = TDB.find "event_nchotomy"
  fun op event_induction _ = ()
  val op event_induction = TDB.find "event_induction"
  fun op event_distinct _ = ()
  val op event_distinct = TDB.find "event_distinct"
  fun op event_case_eq _ = ()
  val op event_case_eq = TDB.find "event_case_eq"
  fun op event_case_def _ = ()
  val op event_case_def = TDB.find "event_case_def"
  fun op event_case_cong _ = ()
  val op event_case_cong = TDB.find "event_case_cong"
  fun op event_TY_DEF _ = () val op event_TY_DEF = TDB.find "event_TY_DEF"
  fun op event_EQ_event _ = ()
  val op event_EQ_event = TDB.find "event_EQ_event"
  fun op event_CASE _ = () val op event_CASE = TDB.find "event_CASE"
  fun op event_BIJ _ = () val op event_BIJ = TDB.find "event_BIJ"
  fun op event_Axiom _ = () val op event_Axiom = TDB.find "event_Axiom"
  fun op eventBytes_def _ = ()
  val op eventBytes_def = TDB.find "eventBytes_def"
  fun op event2num_thm _ = ()
  val op event2num_thm = TDB.find "event2num_thm"
  fun op event2num_num2event _ = ()
  val op event2num_num2event = TDB.find "event2num_num2event"
  fun op event2num_ONTO _ = ()
  val op event2num_ONTO = TDB.find "event2num_ONTO"
  fun op event2num_11 _ = () val op event2num_11 = TDB.find "event2num_11"
  fun op endpointState_updates_eq_literal _ = ()
  val op endpointState_updates_eq_literal = TDB.find
    "endpointState_updates_eq_literal"
  fun op endpointState_size_def _ = ()
  val op endpointState_size_def = TDB.find "endpointState_size_def"
  fun op endpointState_nchotomy _ = ()
  val op endpointState_nchotomy = TDB.find "endpointState_nchotomy"
  fun op endpointState_literal_nchotomy _ = ()
  val op endpointState_literal_nchotomy = TDB.find
    "endpointState_literal_nchotomy"
  fun op endpointState_literal_11 _ = ()
  val op endpointState_literal_11 = TDB.find "endpointState_literal_11"
  fun op endpointState_induction _ = ()
  val op endpointState_induction = TDB.find "endpointState_induction"
  fun op endpointState_fupdfupds_comp _ = ()
  val op endpointState_fupdfupds_comp = TDB.find
    "endpointState_fupdfupds_comp"
  fun op endpointState_fupdfupds _ = ()
  val op endpointState_fupdfupds = TDB.find "endpointState_fupdfupds"
  fun op endpointState_fupdcanon_comp _ = ()
  val op endpointState_fupdcanon_comp = TDB.find
    "endpointState_fupdcanon_comp"
  fun op endpointState_fupdcanon _ = ()
  val op endpointState_fupdcanon = TDB.find "endpointState_fupdcanon"
  fun op endpointState_fn_updates _ = ()
  val op endpointState_fn_updates = TDB.find "endpointState_fn_updates"
  fun op endpointState_component_equality _ = ()
  val op endpointState_component_equality = TDB.find
    "endpointState_component_equality"
  fun op endpointState_case_eq _ = ()
  val op endpointState_case_eq = TDB.find "endpointState_case_eq"
  fun op endpointState_case_def _ = ()
  val op endpointState_case_def = TDB.find "endpointState_case_def"
  fun op endpointState_case_cong _ = ()
  val op endpointState_case_cong = TDB.find "endpointState_case_cong"
  fun op endpointState_accfupds _ = ()
  val op endpointState_accfupds = TDB.find "endpointState_accfupds"
  fun op endpointState_accessors _ = ()
  val op endpointState_accessors = TDB.find "endpointState_accessors"
  fun op endpointState_TY_DEF _ = ()
  val op endpointState_TY_DEF = TDB.find "endpointState_TY_DEF"
  fun op endpointState_Axiom _ = ()
  val op endpointState_Axiom = TDB.find "endpointState_Axiom"
  fun op endpointState_11 _ = ()
  val op endpointState_11 = TDB.find "endpointState_11"
  fun op datatype_serverState _ = ()
  val op datatype_serverState = TDB.find "datatype_serverState"
  fun op datatype_role _ = ()
  val op datatype_role = TDB.find "datatype_role"
  fun op datatype_event _ = ()
  val op datatype_event = TDB.find "datatype_event"
  fun op datatype_endpointState _ = ()
  val op datatype_endpointState = TDB.find "datatype_endpointState"
  fun op datatype_clientState _ = ()
  val op datatype_clientState = TDB.find "datatype_clientState"
  fun op connected_implies_finished _ = ()
  val op connected_implies_finished = TDB.find "connected_implies_finished"
  fun op closed_is_absorbing _ = ()
  val op closed_is_absorbing = TDB.find "closed_is_absorbing"
  fun op client_transition_ind _ = ()
  val op client_transition_ind = TDB.find "client_transition_ind"
  fun op client_transition_def _ = ()
  val op client_transition_def = TDB.find "client_transition_def"
  fun op clientState_size_def _ = ()
  val op clientState_size_def = TDB.find "clientState_size_def"
  fun op clientState_nchotomy _ = ()
  val op clientState_nchotomy = TDB.find "clientState_nchotomy"
  fun op clientState_induction _ = ()
  val op clientState_induction = TDB.find "clientState_induction"
  fun op clientState_distinct _ = ()
  val op clientState_distinct = TDB.find "clientState_distinct"
  fun op clientState_case_eq _ = ()
  val op clientState_case_eq = TDB.find "clientState_case_eq"
  fun op clientState_case_def _ = ()
  val op clientState_case_def = TDB.find "clientState_case_def"
  fun op clientState_case_cong _ = ()
  val op clientState_case_cong = TDB.find "clientState_case_cong"
  fun op clientState_TY_DEF _ = ()
  val op clientState_TY_DEF = TDB.find "clientState_TY_DEF"
  fun op clientState_EQ_clientState _ = ()
  val op clientState_EQ_clientState = TDB.find "clientState_EQ_clientState"
  fun op clientState_CASE _ = ()
  val op clientState_CASE = TDB.find "clientState_CASE"
  fun op clientState_BIJ _ = ()
  val op clientState_BIJ = TDB.find "clientState_BIJ"
  fun op clientState_Axiom _ = ()
  val op clientState_Axiom = TDB.find "clientState_Axiom"
  fun op clientState2num_thm _ = ()
  val op clientState2num_thm = TDB.find "clientState2num_thm"
  fun op clientState2num_num2clientState _ = ()
  val op clientState2num_num2clientState = TDB.find
    "clientState2num_num2clientState"
  fun op clientState2num_ONTO _ = ()
  val op clientState2num_ONTO = TDB.find "clientState2num_ONTO"
  fun op clientState2num_11 _ = ()
  val op clientState2num_11 = TDB.find "clientState2num_11"
  fun op canEmitAppData_def _ = ()
  val op canEmitAppData_def = TDB.find "canEmitAppData_def"
  fun op FORALL_endpointState _ = ()
  val op FORALL_endpointState = TDB.find "FORALL_endpointState"
  fun op EXISTS_endpointState _ = ()
  val op EXISTS_endpointState = TDB.find "EXISTS_endpointState"
  
val _ = if !Globals.print_thy_loads then TextIO.print "done\n" else ()
val _ = Theory.load_complete "tls_handshake"

end
