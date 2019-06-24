% This Source Code Form is subject to the terms of the Mozilla Public
% License, v. 2.0. If a copy of the MPL was not distributed with this
% file, You can obtain one at https://mozilla.org/MPL/2.0/.
% (C) 2019 Andrey Velikiy <agreat22@gmail.com>
% (C) 2019 Fairwaves (edited) 

-module (gsup_encode_decode_test).

-include_lib("eunit/include/eunit.hrl").

-define(TEST_IMSI_IE, 16#01, 16#08, 16#21, 16#43, 16#65, 16#87, 16#09, 16#21, 16#43, 16#f5).
-define(TEST_MSISDN_IE, 16#08, 16#07, 16#91, 16#94, 16#61, 16#46, 16#32, 16#24, 16#43).
-define(TEST_CLASS_SUBSCR_IE, 16#0a, 16#01, 16#01).

missing_params_test() ->
  ?assertError({mandatory_ie_missing,location_cancellation_err,[cause]}, gsup_protocol:decode(<<16#1d, ?TEST_IMSI_IE>>)),
  ?assertError({mandatory_ie_missing,mo_forward_req,[sm_rp_mr,sm_rp_da,sm_rp_oa,sm_rp_ui]}, gsup_protocol:encode(#{message_type => mo_forward_req, imsi => <<"123456">>})).

excess_params_test() ->
  ?assertError({ie_not_expected,location_upd_err,[pdp_info_complete]}, gsup_protocol:encode(#{message_type => location_upd_err,imsi => <<"1234">>,cause => 1,pdp_info_complete => <<>>})).

ie_size_test() ->
  ?assertEqual(#{cause => 255}, gsup_protocol:decode_ie(<<2,1,255>>, #{})),
  ?assertError({ie_length_mismatch,cause,2}, gsup_protocol:decode_ie(<<2,2,0,0>>, #{})),

  ?assertError({ie_value_length_mismatch,cause,-1}, gsup_protocol:encode_ie(#{cause => -1}, <<>>)),
  ?assertEqual(<<2,1,255>>, gsup_protocol:encode_ie(#{cause => 255}, <<>>)),
  ?assertError({ie_value_length_mismatch,cause,256}, gsup_protocol:encode_ie(#{cause => 256}, <<>>)),
  ?assertEqual(<<20,2,255,255>>, gsup_protocol:encode_ie(#{pdp_charging => 16#ffff}, <<>>)),
  ?assertError({ie_value_length_mismatch,pdp_charging,16#10000}, gsup_protocol:encode_ie(#{pdp_charging => 16#10000}, <<>>)),
  ?assertEqual(<<48,4,255,255,255,255>>, gsup_protocol:encode_ie(#{session_id => 16#ffffffff}, <<>>)),
  ?assertError({ie_value_length_mismatch,session_id,16#100000000}, gsup_protocol:encode_ie(#{session_id => 16#100000000}, <<>>)).

sai_req_test() ->
  Bin = <<16#08, ?TEST_IMSI_IE, ?TEST_CLASS_SUBSCR_IE>>,
  Map = #{imsi => <<"123456789012345">>, message_class => 1, message_type => send_auth_info_req},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

sai_err_test() ->
  Bin = <<16#09, ?TEST_IMSI_IE, 16#02, 16#01, 16#07>>,
  Map = #{imsi => <<"123456789012345">>, message_type => send_auth_info_err, cause=>7},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

sai_res_test() ->
  Bin = <<16#0a, ?TEST_IMSI_IE, 
    16#03, 16#22, %% Auth tuple
      16#20, 16#10,
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
        16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10,
      16#21, 16#04,
        16#21, 16#22, 16#23, 16#24,
      16#22, 16#08,
        16#31, 16#32, 16#33, 16#34, 16#35, 16#36, 16#37, 16#38,
    16#03, 16#22, %% Auth tuple
      16#20, 16#10,
        16#81, 16#82, 16#83, 16#84, 16#85, 16#86, 16#87, 16#88,
        16#89, 16#8a, 16#8b, 16#8c, 16#8d, 16#8e, 16#8f, 16#90,
      16#21, 16#04,
        16#a1, 16#a2, 16#a3, 16#a4,
      16#22, 16#08,
        16#b1, 16#b2, 16#b3, 16#b4, 16#b5, 16#b6, 16#b7, 16#b8
  >>,
  Map = #{auth_tuples =>
                       [#{kc => <<16#31, 16#32, 16#33, 16#34, 16#35, 16#36, 16#37, 16#38>>,
                          rand => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
                          sres => <<16#21, 16#22, 16#23, 16#24>>},
                        #{kc => <<16#b1, 16#b2, 16#b3, 16#b4, 16#b5, 16#b6, 16#b7, 16#b8>>,
                          rand =>
                              <<129,130,131,132,133,134,135,136,137,138,139,
                                140,141,142,143,144>>,
                          sres => <<16#a1, 16#a2, 16#a3, 16#a4>>}],
                   imsi => <<"123456789012345">>,
                   message_type => send_auth_info_res},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

sai_res_umts_test() ->
  Bin = <<16#0a, ?TEST_IMSI_IE, 
    16#03, 16#62, %% Auth tuple
      16#20, 16#10, %% rand
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
        16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10,
      16#21, 16#04, %% sres
        16#21, 16#22, 16#23, 16#24,
      16#22, 16#08, %% kc
        16#31, 16#32, 16#33, 16#34, 16#35, 16#36, 16#37, 16#38,
      16#23, 16#10, %% IK (UMTS)
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
        16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10,
      16#24, 16#10, %% CK (UMTS)
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
        16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10,
      16#25, 16#10, %% AUTN (UMTS)
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
        16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10,
      16#27, 16#08, %% RES (UMTS)
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
    16#03, 16#62, %% Auth tuple
      16#20, 16#10, %% rand
        16#a1, 16#a2, 16#a3, 16#a4, 16#a5, 16#a6, 16#a7, 16#a8,
        16#a9, 16#aa, 16#ab, 16#ac, 16#ad, 16#ae, 16#af, 16#10,
      16#21, 16#04, %% sres
        16#b1, 16#b2, 16#b3, 16#b4,
      16#22, 16#08, %% kc
        16#c1, 16#c2, 16#c3, 16#c4, 16#c5, 16#c6, 16#c7, 16#c8,
      16#23, 16#10, %% IK (UMTS)
        16#d1, 16#d2, 16#d3, 16#d4, 16#d5, 16#d6, 16#d7, 16#d8,
        16#d9, 16#da, 16#db, 16#dc, 16#dd, 16#de, 16#df, 16#d0,
      16#24, 16#10, %% CK (UMTS)
        16#e1, 16#e2, 16#e3, 16#e4, 16#e5, 16#e6, 16#e7, 16#e8,
        16#e9, 16#ea, 16#eb, 16#ec, 16#ed, 16#ee, 16#ef, 16#e0,
      16#25, 16#10, %%AUTN (UMTS)
        16#f1, 16#f2, 16#f3, 16#f4, 16#f5, 16#f6, 16#f7, 16#f8,
        16#f9, 16#fa, 16#fb, 16#fc, 16#fd, 16#fe, 16#ff, 16#f0,
      16#27, 16#08,  %%RES (UMTS)
        16#91, 16#92, 16#93, 16#94, 16#95, 16#96, 16#97, 16#98
  >>,
  Map = #{auth_tuples =>
                       [#{autn => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
                          ck => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
                          ik => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
                          kc => <<"12345678">>,
                          rand => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
                          res => <<1,2,3,4,5,6,7,8>>,
                          sres => <<16#21, 16#22, 16#23, 16#24>>},
                        #{autn => <<16#f1, 16#f2, 16#f3, 16#f4, 16#f5, 16#f6, 16#f7, 16#f8,
                                  16#f9, 16#fa, 16#fb, 16#fc, 16#fd, 16#fe, 16#ff, 16#f0>>,
                          ck => <<16#e1, 16#e2, 16#e3, 16#e4, 16#e5, 16#e6, 16#e7, 16#e8,
                                  16#e9, 16#ea, 16#eb, 16#ec, 16#ed, 16#ee, 16#ef, 16#e0>>,
                          ik => <<16#d1, 16#d2, 16#d3, 16#d4, 16#d5, 16#d6, 16#d7, 16#d8,
                                  16#d9, 16#da, 16#db, 16#dc, 16#dd, 16#de, 16#df, 16#d0>>,
                          kc => <<16#c1, 16#c2, 16#c3, 16#c4, 16#c5, 16#c6, 16#c7, 16#c8>>,
                          rand =>
                              <<161,162,163,164,165,166,167,168,169,170,171,
                                172,173,174,175,16>>,
                          res => <<145,146,147,148,149,150,151,152>>,
                          sres => <<16#b1, 16#b2, 16#b3, 16#b4>>}],
                   imsi => <<"123456789012345">>,
                   message_type => send_auth_info_res},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

sai_res_auts_test() ->
  Bin = <<16#0a, ?TEST_IMSI_IE, 
    16#26, 16#0e, %% AUTS (UMTS)
      16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
      16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e,
    16#20, 16#10, %% rand
      16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08,
      16#09, 16#0a, 16#0b, 16#0c, 16#0d, 16#0e, 16#0f, 16#10
  >>,
  Map = #{auts => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14>>,
                   imsi => <<"123456789012345">>,
                   message_type => send_auth_info_res,
                   rand => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

lu_req_test() ->
  Bin = <<16#04, ?TEST_IMSI_IE>>,
  Map = #{imsi => <<"123456789012345">>, message_type => location_upd_req},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

lu_err_test() ->
  Bin = <<16#05, ?TEST_IMSI_IE, 16#02, 16#01, 16#07>>,
  Map = #{imsi => <<"123456789012345">>, message_type => location_upd_err, cause=>7},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

lu_res_test() ->
  Bin = <<16#06, ?TEST_IMSI_IE, ?TEST_MSISDN_IE,
    16#09, 16#07, %% HLR-Number of the subscriber
      16#91, 16#83, 16#52, 16#38, 16#48, 16#83, 16#93,
    16#04, 16#00, %% PDP info complete
    16#05, 16#19,
      16#10, 16#01, 16#01,
      16#11, 16#02, 16#f1, 16#21, %% IPv4
      16#12, 16#09, 16#04, "test", 16#03, "apn",
      16#13, 16#01, 16#02,
      16#14, 16#02, 16#FF, 16#23,
    16#05, 16#11,
      16#10, 16#01, 16#02,
      16#11, 16#02, 16#f1, 16#21, %% IPv4
      16#12, 16#08, 16#03, "foo", 16#03, "apn",
    16#14, 16#02,
      16#AE, 16#FF
  >>,
  Map = #{hlr_number => <<145,131,82,56,72,131,147>>,
                   imsi => <<"123456789012345">>,
                   message_type => location_upd_res,
                   msisdn => <<145,148,97,70,50,36,67>>,
                   pdp_charging => 44799,pdp_info_complete => true,
                   pdp_info_list =>
                       [#{access_point_name =>
                              <<4,116,101,115,116,3,97,112,110>>,
                          pdp_charging => 65315,pdp_context_id => 1,
                          pdp_type => 61729,
                          quality_of_service => <<2>>},
                        #{access_point_name => <<3,102,111,111,3,97,112,110>>,
                          pdp_context_id => 2,pdp_type => 61729}]},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

lc_req_test() ->
  Bin = <<16#1c, ?TEST_IMSI_IE, 16#06, 16#01, 16#00>>,
  Map = #{imsi => <<"123456789012345">>, message_type => location_cancellation_req, cancellation_type => 0},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

lc_err_test() ->
  Bin = <<16#1d, ?TEST_IMSI_IE, 16#02, 16#01, 16#03>>,
  Map = #{imsi => <<"123456789012345">>, message_type => location_cancellation_err, cause=>3},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

lc_res_test() ->
  Bin = <<16#1e, ?TEST_IMSI_IE>>,
  Map = #{imsi => <<"123456789012345">>, message_type => location_cancellation_res},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

purge_ms_req_test() ->
  Bin = <<16#0c, ?TEST_IMSI_IE>>,
  Map = #{imsi => <<"123456789012345">>, message_type => purge_ms_req},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

purge_ms_err_test() ->
  Bin = <<16#0d, ?TEST_IMSI_IE, 16#02, 16#01, 16#03>>,
  Map = #{imsi => <<"123456789012345">>, message_type => purge_ms_err, cause=>3},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

purge_ms_res_test() ->
  Bin = <<16#0e, ?TEST_IMSI_IE, 16#07, 16#00>>,
  Map = #{imsi => <<"123456789012345">>, message_type => purge_ms_res, freeze_p_tmsi => true},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

% dummy_session_test() ->
%   Bin = <<16#2b, ?TEST_IMSI_IE, %% Session ID and state
%     16#30, 16#04, 16#de, 16#ad, 16#be, 16#ef,
%     16#31, 16#01, 16#01
%   >>,
%   Map = #{imsi => <<"123456789012345">>},
%   ?assertEqual(Map, gsup_protocol:decode(Bin)),
%   ?assertEqual(Bin, gsup_protocol:encode(Map)).

ussd_req_test() ->
  Bin = <<16#20, ?TEST_IMSI_IE, %% Session ID and state
    16#30, 16#04, 16#de, 16#ad, 16#be, 16#ef,
    16#31, 16#01, 16#01,

    %% SS/USSD information IE
    16#35, 16#14,
      %% ASN.1 encoded MAP payload
      16#a1, 16#12,
        16#02, 16#01, %% Component: invoke
        16#01, %% invokeID = 1
        %% opCode: processUnstructuredSS-Request
        16#02, 16#01, 16#3b, 16#30, 16#0a, 16#04, 16#01, 16#0f,
        16#04, 16#05, 16#aa, 16#18, 16#0c, 16#36, 16#02
  >>,
  Map = #{imsi => <<"123456789012345">>,message_type => ss_req,
                   session_id => 3735928559,session_state => 1,
                   ss_info =>
                       <<161,18,2,1,1,2,1,59,48,10,4,1,15,4,5,170,24,12,54,2>>},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

ussd_res_test() ->
  Bin = <<16#22, ?TEST_IMSI_IE, %% Session ID and state
    16#30, 16#04, 16#de, 16#ad, 16#be, 16#ef,
    16#31, 16#01, 16#03,

    %% SS/USSD information IE
    16#35, 16#08,
      %% ASN.1 encoded MAP payload
      16#a3, 16#06,
        16#02, 16#01, %% Component: returnError
        16#01, %% invokeID = 1
        %% localValue: unknownAlphabet
        16#02, 16#01, 16#47
  >>,
  Map = #{imsi => <<"123456789012345">>,message_type => ss_res,
                   session_id => 3735928559,session_state => 3,
                   ss_info => <<163,6,2,1,1,2,1,71>>},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

mo_forward_sm_req_test() ->
  Bin = <<16#24, ?TEST_IMSI_IE, %% SM related IEs
    16#40, 16#01, %% SM-RP-MR (Message Reference)
      16#fa,
    16#41, 16#08, %% SM-RP-DA (Destination Address)
      16#03, %% SMSC address
        16#91, 16#52, 16#75, 16#47, 16#99, 16#09, 16#82,
    16#42, 16#01, %% SM-RP-OA (Originating Address)
      16#ff, %% Special case: noSM-RP-OA
    16#43, 16#04, %% SM-RP-UI (TPDU)
      16#de, 16#ad, 16#be, 16#ef
  >>,
  Map = #{imsi => <<"123456789012345">>,
                   message_type => mo_forward_req,
                   sm_rp_da => <<3,145,82,117,71,153,9,130>>,
                   sm_rp_mr => 250,sm_rp_oa => <<16#ff>>,sm_rp_ui => <<16#de, 16#ad, 16#be, 16#ef>>},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

mt_forward_sm_req_test() ->
  Bin = <<16#28, ?TEST_IMSI_IE, %% SM related IEs
    16#40, 16#01, %% SM-RP-MR (Message Reference)
      16#fa,
    16#41, 16#09, %% SM-RP-DA (Destination Address)
      16#01, %% IMSI
        16#21, 16#43, 16#65, 16#87, 16#09, 16#21, 16#43, 16#f5,
    16#42, 16#08, %% SM-RP-OA (Originating Address)
      16#03, %% SMSC address
        16#91, 16#52, 16#75, 16#47, 16#99, 16#09, 16#82,
    16#43, 16#04, %% SM-RP-UI (TPDU)
      16#de, 16#ad, 16#be, 16#ef,
    16#45, 16#01, %% SM-RP-MMS (More Messages to Send)
      16#01
  >>,
  Map = #{imsi => <<"123456789012345">>,
                   message_type => mt_forward_req,
                   sm_rp_da => <<1,33,67,101,135,9,33,67,245>>,
                   sm_rp_mms => 1,sm_rp_mr => 250,
                   sm_rp_oa => <<3,145,82,117,71,153,9,130>>,
                   sm_rp_ui => <<16#de, 16#ad, 16#be, 16#ef>>},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

mo_forward_sm_err_test() ->
  Bin = <<16#25, ?TEST_IMSI_IE, %% SM related IEs
    16#40, 16#01, %% SM-RP-MR (Message Reference)
      16#fa,
    16#44, 16#01, %% SM-RP-Cause value
      16#af
  >>,
  Map = #{imsi => <<"123456789012345">>,
                   message_type => mo_forward_err,sm_rp_cause => 175,
                   sm_rp_mr => 250},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

mt_forward_sm_res_test() ->
  Bin = <<16#2a, ?TEST_IMSI_IE, %% SM related IEs
    16#40, 16#01, %% SM-RP-MR (Message Reference)
      16#fa,
    16#43, 16#04, %% SM-RP-UI (TPDU)
      16#de, 16#ad, 16#be, 16#ef
  >>,
  Map = #{imsi => <<"123456789012345">>,
                   message_type => mt_forward_res,sm_rp_mr => 250,
                   sm_rp_ui => <<16#de, 16#ad, 16#be, 16#ef>>},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

ready_for_sm_req_test() ->
  Bin = <<16#2c, ?TEST_IMSI_IE, 16#46, 16#01, 16#02>>,
  Map = #{imsi => <<"123456789012345">>,
                   message_type => ready_for_sm_req,sm_alert_reason => 2},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

check_imei_req_test() ->
  Bin = <<16#30, ?TEST_IMSI_IE,
    16#50, 16#09, %% IMEI
      16#42, 16#42, 16#42, 16#42, 16#42, 16#42, 16#42, 16#42, 16#42
  >>,
  Map = #{imei => <<16#42, 16#42, 16#42, 16#42, 16#42, 16#42, 16#42, 16#42, 16#42>>,imsi => <<"123456789012345">>,
                   message_type => check_imei_req},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

check_imei_err_test() ->
  Bin = <<16#31, ?TEST_IMSI_IE, 16#02, 16#01, 16#60>>,
  Map = #{cause => 96,imsi => <<"123456789012345">>,
                   message_type => check_imei_err},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

check_imei_res_test() ->
  Bin = <<16#32, ?TEST_IMSI_IE,
    16#51, 16#01,
      16#00 %% OSMO_GSUP_IMEI_RESULT_ACK
  >>,
  Map = #{imei_check_result => 0,imsi => <<"123456789012345">>,
                   message_type => check_imei_res},
  ?assertEqual(Map, gsup_protocol:decode(Bin)),
  ?assertEqual(Bin, gsup_protocol:encode(Map)).

