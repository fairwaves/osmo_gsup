-module (gsup_encode_decode_test).

-include_lib("eunit/include/eunit.hrl").

-define(BINARY_ISD_REQUEST_BAD, <<16,1,8,98,66,130,119,116,88,81,242,5,7,16,1,1,18,2,1,42,8,7,6,148,97,49,100,96,33,40,1,1>>).
-define(BINARY_ISD_REQUEST, <<0,35,238,5, 16,1,8,98,66,130,119,116,88,81,242,4,0,5,7,16,1,1,18,2,1,42,8,7,6,148,97,49,100,96,33,40,1,1>>).
-define(MAP_ISD_REQUEST, #{cn_domain => 1,imsi => <<"262428774785152">>,message_type => insert_sub_data_req,msisdn => <<6,148,97,49,100,96,33>>,pdp_info_list => [#{access_point_name => <<1,42>>,pdp_context_id => 1}], pdp_info_complete => true}).

-define(BINARY_MO_FORWARD_REQUEST, <<0,44,238,5, 36,1,8,98,66,2,0,0,0,128,248,64,1,66,65,5,3,0,137,103,245,66,8,2,6,148,33,3,0,0,136,67,10,5,35,5,0,33,67,245,0,0,0>>).
-define(MAP_MO_FORWARD_REQUEST, #{imsi => <<"262420000000088">>,message_type => mo_forward_req,sm_rp_da => <<3,0,137,103,245>>,sm_rp_mr => 66,sm_rp_oa => <<2,6,148,33,3,0,0,136>>,sm_rp_ui => <<5,35,5,0,33,67,245,0,0,0>>}).

-define(BINARY_SS_REQUEST, <<0,44,238,5, 32,1,8,98,66,2,0,0,0,64,246,48,4,32,0,0,1,49,1,1,53,21,161,19,2,1,5,2,1,59,48,11,4,1,15,4,6,170,81,12,6,27,1>>).
-define(MAP_SS_REQUEST, #{imsi => <<"262420000000046">>,message_type => ss_req,session_id => 536870913,session_state => 1,ss_info => <<161,19,2,1,5,2,1,59,48,11,4,1,15,4,6,170,81,12,6,27,1>>}).

-define(BINARY_SAI_RESULT,<<0,192,238,5, 10,1,8,98,66,2,80,118,115,7,240,3,34,32,16,139,144,41,228,197,232,161,115,52,229,66,150,129,111,14,163,33,4,154,221,96,95,34,8,214,95,14,186,82,93,186,131,3,34,32,16,98,45,225,235,92,202,105,88,14,17,66,100,38,60,70,60,33,4,125,216,104,213,34,8,92,188,236,132,7,137,137,207,3,34,32,16,247,184,92,22,164,154,219,122,73,61,217,228,64,22,207,229,33,4,12,236,133,61,34,8,2,247,249,165,41,173,134,71,3,34,32,16,115,152,209,15,231,72,227,254,143,199,185,130,91,206,171,41,33,4,236,133,225,34,34,8,67,180,13,145,7,174,211,12,3,34,32,16,251,173,219,197,60,132,202,24,53,87,236,186,86,175,231,59,33,4,61,86,38,102,34,8,224,104,249,198,53,145,182,54>>).
-define(MAP_SAI_RESULT, #{auth_tuples => [
    #{kc => <<15447081440312670851:8/unit:8>>,rand => <<185511231865796904634040334886313594531:16/unit:8>>,sres => <<2598199391:4/unit:8>>},
    #{kc => <<6682475998917265871:8/unit:8>>,rand => <<130502579135052156657755432460855559740:16/unit:8>>,sres => <<2111334613:4/unit:8>>},
    #{kc => <<213913995087545927:8/unit:8>>,rand => <<329276565356490492799345768940241866725:16/unit:8>>,sres => <<216827197:4/unit:8>>},
    #{kc => <<4878539212899406604:8/unit:8>>,rand => <<153654688921371376697326139997978274601:16/unit:8>>,sres => <<3968196898:4/unit:8>>},
    #{kc => <<16170449091771348534:8/unit:8>>,rand => <<334538951772921257466553732075468351291:16/unit:8>>,sres => <<1029056102:4/unit:8>>}
  ],imsi => <<"262420056737700">>,message_type => send_auth_info_res}).

isd_request_test() ->
  {ok, {Pkt, <<>>}} = ipa:decode(?BINARY_ISD_REQUEST),
  Map = gsup_protocol:decode(Pkt),
  ?assertEqual(?MAP_ISD_REQUEST, Map),
  Bin = ipa:encode(gsup_protocol:encode(Map)),
  ?assertEqual(?BINARY_ISD_REQUEST, Bin).

mo_forward_request_test() ->
  {ok, {Pkt, <<>>}} = ipa:decode(?BINARY_MO_FORWARD_REQUEST),
  Map = gsup_protocol:decode(Pkt),
  ?assertEqual(?MAP_MO_FORWARD_REQUEST, Map),
  Bin = ipa:encode(gsup_protocol:encode(Map)),
  ?assertEqual(?BINARY_MO_FORWARD_REQUEST, Bin).

ss_request_test() ->
  {ok, {Pkt, <<>>}} = ipa:decode(?BINARY_SS_REQUEST),
  Map = gsup_protocol:decode(Pkt),
  ?assertEqual(?MAP_SS_REQUEST, Map),
  Bin = ipa:encode(gsup_protocol:encode(Map)),
  ?assertEqual(?BINARY_SS_REQUEST, Bin).

sai_result_test() ->
  {ok, {Pkt, <<>>}} = ipa:decode(?BINARY_SAI_RESULT),
  Map = gsup_protocol:decode(Pkt),
  ?assertEqual(?MAP_SAI_RESULT, Map),
  Bin = ipa:encode(gsup_protocol:encode(Map)),
  ?assertEqual(?BINARY_SAI_RESULT, Bin).

missing_params_test() ->
  ?assertError({mandatory_ie_missing,insert_sub_data_req,[pdp_info_complete]}, gsup_protocol:decode(?BINARY_ISD_REQUEST_BAD)),
  ?assertError({mandatory_ie_missing,mo_forward_req,[sm_rp_mr,sm_rp_da,sm_rp_oa,sm_rp_ui]}, gsup_protocol:encode(#{message_type => mo_forward_req, imsi => <<"123456">>})).

excess_params_test() ->
  ?assertError({ie_not_expected,location_upd_err,[pdp_info_complete]}, gsup_protocol:encode(#{message_type => location_upd_err,imsi => <<"1234">>,cause => 1,pdp_info_complete => <<>>})).

ie_size_test() ->
  ?assertEqual(#{cause => 255}, gsup_protocol:decode_ie(<<2,1,255>>, #{})),
  ?assertError({ie_length_mismatch,cause,2}, gsup_protocol:decode_ie(<<2,2,0,0>>, #{})),

  ?assertError({check_size,cause,-1}, gsup_protocol:encode_ie(#{cause => -1}, <<>>)),
  ?assertEqual(<<2,1,255>>, gsup_protocol:encode_ie(#{cause => 255}, <<>>)),
  ?assertError({check_size,cause,256}, gsup_protocol:encode_ie(#{cause => 256}, <<>>)),
  ?assertEqual(<<20,2,255,255>>, gsup_protocol:encode_ie(#{pdp_charging => 16#ffff}, <<>>)),
  ?assertError({check_size,pdp_charging,16#10000}, gsup_protocol:encode_ie(#{pdp_charging => 16#10000}, <<>>)),
  ?assertEqual(<<48,4,255,255,255,255>>, gsup_protocol:encode_ie(#{session_id => 16#ffffffff}, <<>>)),
  ?assertError({check_size,session_id,16#100000000}, gsup_protocol:encode_ie(#{session_id => 16#100000000}, <<>>)).
