-ifndef(GSUP_PROTOCOL).
-define(GSUP_PROTOCOL, true).

-type 'GSUPMessageType'() :: lu_request
                | lu_error
                | lu_result
                | sai_request
                | sai_error
                | sai_result
                | af_report
                | purge_ms_request
                | purge_ms_error
                | purge_ms_result
                | isd_request
                | isd_error
                | isd_result
                | dsd_request
                | dsd_error
                | dsd_result
                | lc_request
                | lc_error
                | lc_result
                | ss_request
                | ss_error
                | ss_result
                | mo_forward_request
                | mo_forward_error
                | mo_forward_result
                | mt_forward_request
                | mt_forward_error
                | mt_forward_result
                | ready_for_sm_request
                | ready_for_sm_error
                | ready_for_sm_result
                | ci_request
                | ci_error
                | ci_result.

-type 'GSUPMessage'() :: #{
  message_type := 'GSUPMessageType'(),
  imsi := binary(),
  cause => integer(),
  auth_tuples => [#{
    rand := binary(),
    sres := binary(),
    kc := binary(),
    ik => binary(),
    ck => binary(),
    autn => binary(),
    res => binary()
  }] | [],
  pdp_info_complete => binary(),
  pdp_info_list => [#{
    pdp_context_id => integer(),
    pdp_type => integer(),
    pdp_charging => integer(),
    access_point_name => binary(),
    quality_of_service => binary()
  }],
  cancellation_type => integer(),
  freeze_p_tmsi => binary(),  
  msisdn => binary(),
  hlr_number => binary(),
  pdp_context_id => integer(),
  pdp_charging => integer(),
  rand => binary(),
  auts => binary(),
  cn_domain => integer(),
  session_id => integer(),
  session_state => integer(),
  ss_info => binary(),
  sm_rp_mr => integer(),
  sm_rp_da => {imsi | msisdn | smsc, binary()} | {omit, undefined},
  sm_rp_oa => {imsi | msisdn | smsc, binary()} | {omit, undefined},
  sm_rp_ui => binary(),
  sm_rp_cause => integer(),
  sm_rp_mms => integer(),
  sm_alert_reason => integer(),
  imei => binary(),
  imei_check_result => integer()
}.

-define(OSMO_EXT, 16#ee).
-define(GSUP_OSMO_EXT, 16#05).

-define(SESSION_STATE_BEGIN, 1).
-define(SESSION_STATE_CONTINUE, 2).
-define(SESSION_STATE_END, 3).

-define(IMSI_HEX, 16#01).
-define(CAUSE_HEX, 16#02).
-define(AUTH_TUPLE_HEX, 16#03).
-define(PDP_INFO_COMPLETE_HEX, 16#04).
-define(PDP_INFO_HEX, 16#05).
-define(CANCELLATION_TYPE_HEX, 16#06).
-define(FREEZE_P_TMSI_HEX, 16#07).
-define(MSISDN_HEX, 16#08).
-define(HLR_NUMBER_HEX, 16#09).
-define(PDP_CONTEXT_ID_HEX, 16#10).
-define(PDP_TYPE_HEX, 16#11).
-define(ACCESS_POINT_NAME_HEX, 16#12).
-define(QUALITY_OF_SERVICE_HEX, 16#13).
-define(PDP_CHARGING_HEX, 16#14).
-define(RAND_HEX, 16#20).
-define(SRES_HEX, 16#21).
-define(KC_HEX, 16#22).
-define(IK_HEX, 16#23).
-define(CK_HEX, 16#24).
-define(AUTN_HEX, 16#25).
-define(AUTS_HEX, 16#26).
-define(RES_HEX, 16#27).
-define(CN_DOMAIN_HEX, 16#28).
-define(SESSION_ID_HEX, 16#30).
-define(SESSION_STATE_HEX, 16#31).
-define(SS_INFO_HEX, 16#35).
-define(SM_RP_MR_HEX, 16#40).
-define(SM_RP_DA_HEX, 16#41).
-define(SM_RP_OA_HEX, 16#42).
-define(SM_RP_UI_HEX, 16#43).
-define(SM_RP_CAUSE_HEX, 16#44).
-define(SM_RP_MMS_HEX, 16#45).
-define(SM_ALERT_REASON_HEX, 16#46).
-define(IMEI_HEX, 16#50).
-define(IMEI_CHECK_RESULT_HEX, 16#51).

-define (GSUP_MESSAGES(), #{
  16#04 => #{message_type => lu_request, mandatory => [imsi], possible => [imsi, cn_domain]},
  16#05 => #{message_type => lu_error, mandatory => [imsi, cause], possible => [imsi, cause]},
  16#06 => #{message_type => lu_result, mandatory => [imsi], possible => [imsi, msisdn, hlr_number, pdp_info_complete, pdp_info_list]},
  16#08 => #{message_type => sai_request, mandatory => [imsi], possible => [imsi, cn_domain, auts, rand]},
  16#09 => #{message_type => sai_error, mandatory => [imsi, cause], possible => [imsi, cause]},
  16#0a => #{message_type => sai_result, mandatory => [imsi], possible => [imsi, auth_tuples]},
  16#0b => #{message_type => af_report, mandatory => [imsi], possible => [imsi, cn_domain]},
  16#0c => #{message_type => purge_ms_request, mandatory => [imsi, hlr_number], possible => [imsi, cn_domain, hlr_number]},
  16#0d => #{message_type => purge_ms_error, mandatory => [imsi, cause], possible => [imsi, cause]},
  16#0e => #{message_type => purge_ms_result, mandatory => [imsi, freeze_p_tmsi], possible => [imsi, freeze_p_tmsi]},
  16#10 => #{message_type => isd_request, mandatory => [imsi, pdp_info_complete], possible => [imsi, cn_domain, msisdn, hlr_number, pdp_info_complete, pdp_info_list, pdp_charging]},
  16#11 => #{message_type => isd_error, mandatory => [imsi, cause], possible => [imsi, cause]},
  16#12 => #{message_type => isd_result, mandatory => [imsi], possible => [imsi]},
  16#14 => #{message_type => dsd_request, mandatory => [imsi], possible => [imsi, cn_domain, pdp_context_id]},
  16#15 => #{message_type => dsd_error, mandatory => [imsi, cause], possible => [imsi, cause]},
  16#16 => #{message_type => dsd_result, mandatory => [imsi], possible => [imsi]},
  16#1c => #{message_type => lc_request, mandatory => [imsi], possible => [imsi, cn_domain, cancellation_type]},
  16#1d => #{message_type => lc_error, mandatory => [imsi, cause], possible => [imsi, cn_domain]},
  16#1e => #{message_type => lc_result, mandatory => [imsi], possible => [imsi, cn_domain]},
  16#20 => #{message_type => ss_request, mandatory => [session_id, session_state, imsi], possible => [imsi, session_id, session_state, ss_info]},
  16#21 => #{message_type => ss_error, mandatory => [session_id, session_state, imsi, cause], possible => [imsi, cause, session_id, session_state]},
  16#22 => #{message_type => ss_result, mandatory => [session_id, session_state, imsi], possible => [imsi, session_id, session_state, ss_info]},
  16#24 => #{message_type => mo_forward_request, mandatory => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui], possible => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui]},
  16#25 => #{message_type => mo_forward_error, mandatory => [sm_rp_mr, imsi, sm_rp_cause], possible => [sm_rp_mr, imsi, sm_rp_cause, sm_rp_ui]},
  16#26 => #{message_type => mo_forward_result, mandatory => [sm_rp_mr, imsi], possible => [sm_rp_mr, imsi]},
  16#28 => #{message_type => mt_forward_request, mandatory => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui], possible => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui, sm_rp_mms]},
  16#29 => #{message_type => mt_forward_error, mandatory => [sm_rp_mr, imsi, sm_rp_cause], possible => [sm_rp_mr, imsi, sm_rp_cause, sm_rp_ui]},
  16#2a => #{message_type => mt_forward_result, mandatory => [sm_rp_mr, imsi], possible => [sm_rp_mr, imsi]},
  16#2c => #{message_type => ready_for_sm_request, mandatory => [imsi, sm_rp_mr, sm_alert_reason], possible => [imsi, sm_rp_mr, sm_alert_reason]},
  16#2d => #{message_type => ready_for_sm_error, mandatory => [imsi, sm_rp_mr, sm_sm_rp_cause], possible => [imsi, sm_rp_mr, sm_sm_rp_cause, sm_rp_ui]},
  16#2e => #{message_type => ready_for_sm_result, mandatory => [imsi, sm_rp_mr], possible => [imsi, sm_rp_mr]},
  16#30 => #{message_type => ci_request, mandatory => [imsi, imei], possible => [imsi, imei]},
  16#31 => #{message_type => ci_error, mandatory => [imsi, cause], possible => [imsi, cause]},
  16#32 => #{message_type => ci_result, mandatory => [imsi, imei_check_result], possible => [imsi, imei_check_result]}
}).

-endif.
