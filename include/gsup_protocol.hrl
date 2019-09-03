% This Source Code Form is subject to the terms of the Mozilla Public
% License, v. 2.0. If a copy of the MPL was not distributed with this
% file, You can obtain one at https://mozilla.org/MPL/2.0/.
% (C) 2019 Andrey Velikiy <agreat22@gmail.com>
% (C) 2019 Fairwaves (edited) 

-ifndef(GSUP_PROTOCOL).
-define(GSUP_PROTOCOL, true).

-type 'GSUPMessageType'() :: location_upd_req
                  | location_upd_err
                  | location_upd_res
                  | send_auth_info_req
                  | send_auth_info_err
                  | send_auth_info_res
                  | auth_failure_report
                  | purge_ms_req
                  | purge_ms_err
                  | purge_ms_res
                  | insert_sub_data_req
                  | insert_sub_data_err
                  | insert_sub_data_res
                  | delete_sub_data_req
                  | delete_sub_data_err
                  | delete_sub_data_res
                  | location_cancellation_req
                  | location_cancellation_err
                  | location_cancellation_res
                  | ss_req
                  | ss_err
                  | ss_res
                  | mo_forward_sm_req
                  | mo_forward_sm_err
                  | mo_forward_sm_res
                  | mt_forward_sm_req
                  | mt_forward_sm_err
                  | mt_forward_sm_res
                  | ready_for_sm_req
                  | ready_for_sm_err
                  | ready_for_sm_res
                  | check_imei_req
                  | check_imei_err
                  | check_imei_res
                  | e_prepare_handover_req
                  | e_prepare_handover_err
                  | e_prepare_handover_res
                  | e_prepare_subseq_handover_req
                  | e_prepare_subseq_handover_err
                  | e_prepare_subseq_handover_res
                  | e_send_end_signal_req
                  | e_send_end_signal_err
                  | e_send_end_signal_res
                  | e_process_access_signalling_req
                  | e_forward_access_signalling_req
                  | e_close
                  | e_abort
                  | e_routing_err.

-type 'GSUPAuthTuple'() :: #{
  rand := binary(),
  sres := binary(),
  kc := binary(),
  ik => binary(),
  ck => binary(),
  autn => binary(),
  res => binary()
}.

-type 'GSUPPdpInfo'() :: #{
  pdp_context_id => integer(),
  pdp_type => integer(),
  access_point_name => binary(),
  quality_of_service => binary(),
  pdp_charging => integer()
}.

-type 'GSUPMessage'() :: #{
  message_type := 'GSUPMessageType'(),
  imsi := binary(),
  cause => integer(),
  auth_tuples => ['GSUPAuthTuple'()],
  pdp_info_complete => true,
  pdp_info_list => ['GSUPPdpInfo'()],
  cancellation_type => integer(),
  freeze_p_tmsi => true,  
  msisdn => binary(),
  hlr_number => binary(),
  pdp_context_id => [integer()],
  pdp_charging => integer(),
  rand => binary(),
  auts => binary(),
  cn_domain => integer(),
  session_id => integer(),
  session_state => integer(),
  ss_info => binary(),
  sm_rp_mr => integer(),
  sm_rp_da => binary(),
  sm_rp_oa => binary(),
  sm_rp_ui => binary(),
  sm_rp_cause => integer(),
  sm_rp_mms => integer(),
  sm_alert_reason => integer(),
  imei => binary(),
  imei_check_result => integer(),
  message_class => integer(),
  source_name => binary(),
  destination_name => binary(),
  an_apdu => binary(),
  rr_cause => integer(),
  session_management_cause => integer(),
  bssap_cause => integer()
}.

-define(SESSION_STATE_BEGIN, 1).
-define(SESSION_STATE_CONTINUE, 2).
-define(SESSION_STATE_END, 3).

-define(IMSI, 16#01).
-define(CAUSE, 16#02).
-define(AUTH_TUPLE, 16#03).
-define(PDP_INFO_COMPLETE, 16#04).
-define(PDP_INFO, 16#05).
-define(CANCELLATION_TYPE, 16#06).
-define(FREEZE_P_TMSI, 16#07).
-define(MSISDN, 16#08).
-define(HLR_NUMBER, 16#09).
-define(MESSAGE_CLASS, 16#0a).
-define(PDP_CONTEXT_ID, 16#10).
-define(PDP_TYPE, 16#11).
-define(ACCESS_POINT_NAME, 16#12).
-define(QUALITY_OF_SERVICE, 16#13).
-define(PDP_CHARGING, 16#14).
-define(RAND, 16#20).
-define(SRES, 16#21).
-define(KC, 16#22).
-define(IK, 16#23).
-define(CK, 16#24).
-define(AUTN, 16#25).
-define(AUTS, 16#26).
-define(RES, 16#27).
-define(CN_DOMAIN, 16#28).
-define(SESSION_ID, 16#30).
-define(SESSION_STATE, 16#31).
-define(SS_INFO, 16#35).
-define(SM_RP_MR, 16#40).
-define(SM_RP_DA, 16#41).
-define(SM_RP_OA, 16#42).
-define(SM_RP_UI, 16#43).
-define(SM_RP_CAUSE, 16#44).
-define(SM_RP_MMS, 16#45).
-define(SM_ALERT_REASON, 16#46).
-define(IMEI, 16#50).
-define(IMEI_CHECK_RESULT, 16#51).
-define(SOURCE_NAME, 16#60).
-define(DESTINATION_NAME, 16#61).
-define(AN_APDU, 16#62).
-define(RR_CAUSE, 16#63).
-define(BSSAP_CAUSE, 16#64).
-define(SESSION_MANAGEMENT_CAUSE, 16#65).

-define(MANDATORY_DEFAULT, [imsi, message_type]).

-define(OPTIONAL_DEFAULT, [message_class]).

-define (GSUP_MESSAGES(), #{
  16#04 => #{message_type => location_upd_req, mandatory => [], optional => [cn_domain]},
  16#05 => #{message_type => location_upd_err, mandatory => [cause]},
  16#06 => #{message_type => location_upd_res, mandatory => [], optional => [msisdn, hlr_number, pdp_info_complete, pdp_info_list, pdp_charging]},
  16#08 => #{message_type => send_auth_info_req, mandatory => [], optional => [cn_domain, auts, rand]},
  16#09 => #{message_type => send_auth_info_err, mandatory => [cause]},
  16#0a => #{message_type => send_auth_info_res, mandatory => [], optional => [auth_tuples, auts, rand]},
  16#0b => #{message_type => auth_failure_report, mandatory => [], optional => [cn_domain]},
  16#0c => #{message_type => purge_ms_req, mandatory => [], optional => [cn_domain, hlr_number]},
  16#0d => #{message_type => purge_ms_err, mandatory => [cause]},
  16#0e => #{message_type => purge_ms_res, mandatory => [freeze_p_tmsi]},
  16#10 => #{message_type => insert_sub_data_req, mandatory => [pdp_info_complete], optional => [cn_domain, msisdn, hlr_number, pdp_info_list, pdp_charging]},
  16#11 => #{message_type => insert_sub_data_err, mandatory => [cause]},
  16#12 => #{message_type => insert_sub_data_res, mandatory => []},
  16#14 => #{message_type => delete_sub_data_req, mandatory => [], optional => [cn_domain, pdp_context_id]},
  16#15 => #{message_type => delete_sub_data_err, mandatory => [cause]},
  16#16 => #{message_type => delete_sub_data_res, mandatory => []},
  16#1c => #{message_type => location_cancellation_req, mandatory => [], optional => [cn_domain, cancellation_type]},
  16#1d => #{message_type => location_cancellation_err, mandatory => [cause]},
  16#1e => #{message_type => location_cancellation_res, mandatory => [], optional => [cn_domain]},
  16#20 => #{message_type => ss_req, mandatory => [session_id, session_state], optional => [ss_info]},
  16#21 => #{message_type => ss_err, mandatory => [session_id, session_state, cause]},
  16#22 => #{message_type => ss_res, mandatory => [session_id, session_state], optional => [ss_info]},
  16#24 => #{message_type => mo_forward_sm_req, mandatory => [sm_rp_mr, sm_rp_da, sm_rp_oa, sm_rp_ui]},
  16#25 => #{message_type => mo_forward_sm_err, mandatory => [sm_rp_mr, sm_rp_cause], optional => [sm_rp_ui]},
  16#26 => #{message_type => mo_forward_sm_res, mandatory => [sm_rp_mr], optional => [sm_rp_ui]},
  16#28 => #{message_type => mt_forward_sm_req, mandatory => [sm_rp_mr, sm_rp_da, sm_rp_oa, sm_rp_ui], optional => [sm_rp_mms]},
  16#29 => #{message_type => mt_forward_sm_err, mandatory => [sm_rp_mr, sm_rp_cause], optional => [sm_rp_ui]},
  16#2a => #{message_type => mt_forward_sm_res, mandatory => [sm_rp_mr], optional => [sm_rp_ui]},
  16#2c => #{message_type => ready_for_sm_req, mandatory => [sm_alert_reason]},
  16#2d => #{message_type => ready_for_sm_err, mandatory => [sm_rp_cause], optional => [sm_rp_ui]},
  16#2e => #{message_type => ready_for_sm_res, mandatory => []},
  16#30 => #{message_type => check_imei_req, mandatory => [imei]},
  16#31 => #{message_type => check_imei_err, mandatory => [cause]},
  16#32 => #{message_type => check_imei_res, mandatory => [imei_check_result]},
  16#34 => #{message_type => e_prepare_handover_req, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#35 => #{message_type => e_prepare_handover_err, mandatory => [message_class, source_name, destination_name, an_apdu, bssap_cause], optional => [session_id, session_state]},
  16#36 => #{message_type => e_prepare_handover_res, mandatory => [message_class, source_name, destination_name, an_apdu, msisdn], optional => [session_id, session_state]},
  16#38 => #{message_type => e_prepare_subseq_handover_req, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#39 => #{message_type => e_prepare_subseq_handover_err, mandatory => [message_class, source_name, destination_name, an_apdu, bssap_cause], optional => [session_id, session_state]},
  16#3a => #{message_type => e_prepare_subseq_handover_res, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#3c => #{message_type => e_send_end_signal_req, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#3d => #{message_type => e_send_end_signal_err, mandatory => [message_class, source_name, destination_name, an_apdu, bssap_cause], optional => [session_id, session_state]},
  16#3e => #{message_type => e_send_end_signal_res, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#40 => #{message_type => e_process_access_signalling_req, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#44 => #{message_type => e_forward_access_signalling_req, mandatory => [message_class, source_name, destination_name, an_apdu], optional => [session_id, session_state]},
  16#47 => #{message_type => e_close, mandatory => [message_class, source_name, destination_name], optional => [session_id, session_state]},
  16#4b => #{message_type => e_abort, mandatory => [message_class, bssap_cause], optional => [session_id, session_state]},
  16#4e => #{message_type => e_routing_err, mandatory => [message_class, source_name, destination_name], optional => [session_id, session_state]}
}).

-define(AUTH_TUPLE_MANDATORY, [rand, sres, kc]).
-define(AUTH_TUPLE_OPTIONAL, [ik, ck, autn, res]).
-define(PDP_INFO_MANDATORY, []).
-define(PDP_INFO_OPTIONAL, [pdp_context_id, pdp_type, access_point_name, quality_of_service, pdp_charging]).

-endif.
