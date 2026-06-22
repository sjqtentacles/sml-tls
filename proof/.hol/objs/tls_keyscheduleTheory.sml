structure tls_keyscheduleTheory :> tls_keyscheduleTheory =
struct
  
  val _ = if !Globals.print_thy_loads
    then TextIO.print "Loading tls_keyscheduleTheory ... "
    else ()
  
  open Type Term Thm
  local open wordsTheory in end;
  
  structure TDB = struct
    val path =
      OS.Path.base (#(FILE)) ^ ".dat"
    val timestamp = HOLFileSys.modTime path
    val thydata = 
      TheoryReader.load_thydata {
        thyname = "tls_keyschedule",
        hash = "1d680c7cb968132dd9d608a59c2d721447a9c7eb",
        path = path
      }
    fun find s = #1 (valOf (Symtab.lookup thydata s))
  end
  val () = Theory.record_metadata
    "tls_keyschedule" {timestamp=TDB.timestamp, path=TDB.path}
  
  fun op zeros_def _ = () val op zeros_def = TDB.find "zeros_def"
  fun op w16_to_bytes_def _ = ()
  val op w16_to_bytes_def = TDB.find "w16_to_bytes_def"
  fun op trafficKey_def _ = ()
  val op trafficKey_def = TDB.find "trafficKey_def"
  fun op trafficIv_def _ = ()
  val op trafficIv_def = TDB.find "trafficIv_def"
  fun op tls13Prefix_def _ = ()
  val op tls13Prefix_def = TDB.find "tls13Prefix_def"
  fun op string_to_word8_def _ = ()
  val op string_to_word8_def = TDB.find "string_to_word8_def"
  fun op sha256_def _ = () val op sha256_def = TDB.find "sha256_def"
  fun op serverCertVerifyContext_def _ = ()
  val op serverCertVerifyContext_def = TDB.find
    "serverCertVerifyContext_def"
  fun op schedule_def _ = () val op schedule_def = TDB.find "schedule_def"
  fun op rfc8448_schedule _ = ()
  val op rfc8448_schedule = TDB.find "rfc8448_schedule"
  fun op rfc8448_handshakeSecret _ = ()
  val op rfc8448_handshakeSecret = TDB.find "rfc8448_handshakeSecret"
  fun op rfc8448_earlySecret _ = ()
  val op rfc8448_earlySecret = TDB.find "rfc8448_earlySecret"
  fun op recordtype_keySchedule_seldef_serverHandshakeSecret_fupd_def _ =
    ()
  val op recordtype_keySchedule_seldef_serverHandshakeSecret_fupd_def =
    TDB.find "recordtype_keySchedule_seldef_serverHandshakeSecret_fupd_def"
  fun op recordtype_keySchedule_seldef_serverHandshakeSecret_def _ = ()
  val op recordtype_keySchedule_seldef_serverHandshakeSecret_def = TDB.find
    "recordtype_keySchedule_seldef_serverHandshakeSecret_def"
  fun op recordtype_keySchedule_seldef_serverAppSecret_fupd_def _ = ()
  val op recordtype_keySchedule_seldef_serverAppSecret_fupd_def = TDB.find
    "recordtype_keySchedule_seldef_serverAppSecret_fupd_def"
  fun op recordtype_keySchedule_seldef_serverAppSecret_def _ = ()
  val op recordtype_keySchedule_seldef_serverAppSecret_def = TDB.find
    "recordtype_keySchedule_seldef_serverAppSecret_def"
  fun op recordtype_keySchedule_seldef_masterSecret_fupd_def _ = ()
  val op recordtype_keySchedule_seldef_masterSecret_fupd_def = TDB.find
    "recordtype_keySchedule_seldef_masterSecret_fupd_def"
  fun op recordtype_keySchedule_seldef_masterSecret_def _ = ()
  val op recordtype_keySchedule_seldef_masterSecret_def = TDB.find
    "recordtype_keySchedule_seldef_masterSecret_def"
  fun op recordtype_keySchedule_seldef_handshakeSecret_fupd_def _ = ()
  val op recordtype_keySchedule_seldef_handshakeSecret_fupd_def = TDB.find
    "recordtype_keySchedule_seldef_handshakeSecret_fupd_def"
  fun op recordtype_keySchedule_seldef_handshakeSecret_def _ = ()
  val op recordtype_keySchedule_seldef_handshakeSecret_def = TDB.find
    "recordtype_keySchedule_seldef_handshakeSecret_def"
  fun op recordtype_keySchedule_seldef_earlySecret_fupd_def _ = ()
  val op recordtype_keySchedule_seldef_earlySecret_fupd_def = TDB.find
    "recordtype_keySchedule_seldef_earlySecret_fupd_def"
  fun op recordtype_keySchedule_seldef_earlySecret_def _ = ()
  val op recordtype_keySchedule_seldef_earlySecret_def = TDB.find
    "recordtype_keySchedule_seldef_earlySecret_def"
  fun op recordtype_keySchedule_seldef_clientHandshakeSecret_fupd_def _ =
    ()
  val op recordtype_keySchedule_seldef_clientHandshakeSecret_fupd_def =
    TDB.find "recordtype_keySchedule_seldef_clientHandshakeSecret_fupd_def"
  fun op recordtype_keySchedule_seldef_clientHandshakeSecret_def _ = ()
  val op recordtype_keySchedule_seldef_clientHandshakeSecret_def = TDB.find
    "recordtype_keySchedule_seldef_clientHandshakeSecret_def"
  fun op recordtype_keySchedule_seldef_clientAppSecret_fupd_def _ = ()
  val op recordtype_keySchedule_seldef_clientAppSecret_fupd_def = TDB.find
    "recordtype_keySchedule_seldef_clientAppSecret_fupd_def"
  fun op recordtype_keySchedule_seldef_clientAppSecret_def _ = ()
  val op recordtype_keySchedule_seldef_clientAppSecret_def = TDB.find
    "recordtype_keySchedule_seldef_clientAppSecret_def"
  fun op masterSecret_def _ = ()
  val op masterSecret_def = TDB.find "masterSecret_def"
  fun op keySchedule_updates_eq_literal _ = ()
  val op keySchedule_updates_eq_literal = TDB.find
    "keySchedule_updates_eq_literal"
  fun op keySchedule_size_def _ = ()
  val op keySchedule_size_def = TDB.find "keySchedule_size_def"
  fun op keySchedule_nchotomy _ = ()
  val op keySchedule_nchotomy = TDB.find "keySchedule_nchotomy"
  fun op keySchedule_literal_nchotomy _ = ()
  val op keySchedule_literal_nchotomy = TDB.find
    "keySchedule_literal_nchotomy"
  fun op keySchedule_literal_11 _ = ()
  val op keySchedule_literal_11 = TDB.find "keySchedule_literal_11"
  fun op keySchedule_induction _ = ()
  val op keySchedule_induction = TDB.find "keySchedule_induction"
  fun op keySchedule_fupdfupds_comp _ = ()
  val op keySchedule_fupdfupds_comp = TDB.find "keySchedule_fupdfupds_comp"
  fun op keySchedule_fupdfupds _ = ()
  val op keySchedule_fupdfupds = TDB.find "keySchedule_fupdfupds"
  fun op keySchedule_fupdcanon_comp _ = ()
  val op keySchedule_fupdcanon_comp = TDB.find "keySchedule_fupdcanon_comp"
  fun op keySchedule_fupdcanon _ = ()
  val op keySchedule_fupdcanon = TDB.find "keySchedule_fupdcanon"
  fun op keySchedule_fn_updates _ = ()
  val op keySchedule_fn_updates = TDB.find "keySchedule_fn_updates"
  fun op keySchedule_component_equality _ = ()
  val op keySchedule_component_equality = TDB.find
    "keySchedule_component_equality"
  fun op keySchedule_case_eq _ = ()
  val op keySchedule_case_eq = TDB.find "keySchedule_case_eq"
  fun op keySchedule_case_def _ = ()
  val op keySchedule_case_def = TDB.find "keySchedule_case_def"
  fun op keySchedule_case_cong _ = ()
  val op keySchedule_case_cong = TDB.find "keySchedule_case_cong"
  fun op keySchedule_accfupds _ = ()
  val op keySchedule_accfupds = TDB.find "keySchedule_accfupds"
  fun op keySchedule_accessors _ = ()
  val op keySchedule_accessors = TDB.find "keySchedule_accessors"
  fun op keySchedule_TY_DEF _ = ()
  val op keySchedule_TY_DEF = TDB.find "keySchedule_TY_DEF"
  fun op keySchedule_Axiom _ = ()
  val op keySchedule_Axiom = TDB.find "keySchedule_Axiom"
  fun op keySchedule_11 _ = ()
  val op keySchedule_11 = TDB.find "keySchedule_11"
  fun op hmac_sha256_def _ = ()
  val op hmac_sha256_def = TDB.find "hmac_sha256_def"
  fun op hkdfExtract_def _ = ()
  val op hkdfExtract_def = TDB.find "hkdfExtract_def"
  fun op hkdfExpand_def _ = ()
  val op hkdfExpand_def = TDB.find "hkdfExpand_def"
  fun op hkdfExpandLabel_def _ = ()
  val op hkdfExpandLabel_def = TDB.find "hkdfExpandLabel_def"
  fun op hex_to_word8_def _ = ()
  val op hex_to_word8_def = TDB.find "hex_to_word8_def"
  fun op hashLen_def _ = () val op hashLen_def = TDB.find "hashLen_def"
  fun op handshakeSecret_def _ = ()
  val op handshakeSecret_def = TDB.find "handshakeSecret_def"
  fun op finishedVerifyData_def _ = ()
  val op finishedVerifyData_def = TDB.find "finishedVerifyData_def"
  fun op finishedKey_def _ = ()
  val op finishedKey_def = TDB.find "finishedKey_def"
  fun op earlySecret_def _ = ()
  val op earlySecret_def = TDB.find "earlySecret_def"
  fun op deriveSecret_def _ = ()
  val op deriveSecret_def = TDB.find "deriveSecret_def"
  fun op deriveLabel_def _ = ()
  val op deriveLabel_def = TDB.find "deriveLabel_def"
  fun op datatype_keySchedule _ = ()
  val op datatype_keySchedule = TDB.find "datatype_keySchedule"
  fun op clientCertVerifyContext_def _ = ()
  val op clientCertVerifyContext_def = TDB.find
    "clientCertVerifyContext_def"
  fun op certificateVerifyPrefix_def _ = ()
  val op certificateVerifyPrefix_def = TDB.find
    "certificateVerifyPrefix_def"
  fun op certificateVerifyInput_def _ = ()
  val op certificateVerifyInput_def = TDB.find "certificateVerifyInput_def"
  fun op buildHkdfLabel_def _ = ()
  val op buildHkdfLabel_def = TDB.find "buildHkdfLabel_def"
  fun op FORALL_keySchedule _ = ()
  val op FORALL_keySchedule = TDB.find "FORALL_keySchedule"
  fun op EXISTS_keySchedule _ = ()
  val op EXISTS_keySchedule = TDB.find "EXISTS_keySchedule"
  
val _ = if !Globals.print_thy_loads then TextIO.print "done\n" else ()
val _ = Theory.load_complete "tls_keyschedule"

end
