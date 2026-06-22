signature tls_keyscheduleTheory =
sig
  type thm = Thm.thm
  
  (*  Definitions  *)
    val buildHkdfLabel_def : thm
    val certificateVerifyInput_def : thm
    val certificateVerifyPrefix_def : thm
    val clientCertVerifyContext_def : thm
    val deriveLabel_def : thm
    val deriveSecret_def : thm
    val earlySecret_def : thm
    val finishedKey_def : thm
    val finishedVerifyData_def : thm
    val handshakeSecret_def : thm
    val hashLen_def : thm
    val hex_to_word8_def : thm
    val hkdfExpandLabel_def : thm
    val hkdfExpand_def : thm
    val hkdfExtract_def : thm
    val hmac_sha256_def : thm
    val keySchedule_TY_DEF : thm
    val keySchedule_case_def : thm
    val keySchedule_size_def : thm
    val masterSecret_def : thm
    val recordtype_keySchedule_seldef_clientAppSecret_def : thm
    val recordtype_keySchedule_seldef_clientAppSecret_fupd_def : thm
    val recordtype_keySchedule_seldef_clientHandshakeSecret_def : thm
    val recordtype_keySchedule_seldef_clientHandshakeSecret_fupd_def : thm
    val recordtype_keySchedule_seldef_earlySecret_def : thm
    val recordtype_keySchedule_seldef_earlySecret_fupd_def : thm
    val recordtype_keySchedule_seldef_handshakeSecret_def : thm
    val recordtype_keySchedule_seldef_handshakeSecret_fupd_def : thm
    val recordtype_keySchedule_seldef_masterSecret_def : thm
    val recordtype_keySchedule_seldef_masterSecret_fupd_def : thm
    val recordtype_keySchedule_seldef_serverAppSecret_def : thm
    val recordtype_keySchedule_seldef_serverAppSecret_fupd_def : thm
    val recordtype_keySchedule_seldef_serverHandshakeSecret_def : thm
    val recordtype_keySchedule_seldef_serverHandshakeSecret_fupd_def : thm
    val schedule_def : thm
    val serverCertVerifyContext_def : thm
    val sha256_def : thm
    val string_to_word8_def : thm
    val tls13Prefix_def : thm
    val trafficIv_def : thm
    val trafficKey_def : thm
    val w16_to_bytes_def : thm
    val zeros_def : thm
  
  (*  Theorems  *)
    val EXISTS_keySchedule : thm
    val FORALL_keySchedule : thm
    val datatype_keySchedule : thm
    val keySchedule_11 : thm
    val keySchedule_Axiom : thm
    val keySchedule_accessors : thm
    val keySchedule_accfupds : thm
    val keySchedule_case_cong : thm
    val keySchedule_case_eq : thm
    val keySchedule_component_equality : thm
    val keySchedule_fn_updates : thm
    val keySchedule_fupdcanon : thm
    val keySchedule_fupdcanon_comp : thm
    val keySchedule_fupdfupds : thm
    val keySchedule_fupdfupds_comp : thm
    val keySchedule_induction : thm
    val keySchedule_literal_11 : thm
    val keySchedule_literal_nchotomy : thm
    val keySchedule_nchotomy : thm
    val keySchedule_updates_eq_literal : thm
    val rfc8448_earlySecret : thm
    val rfc8448_handshakeSecret : thm
    val rfc8448_schedule : thm
end
