-module(gsup_encoder_tests).
-include_lib("eunit/include/eunit.hrl").

-define(setup(F), {setup, fun start/0, fun stop/1, F}).

-define(BINARY_INSERT_SUBSCRIBER_DATA_REQUEST, <<0,33,238,5,16,1,8,98,66,130,119,116,88,81,242,40,1,1,8,7,6,148,97,49,100,96,33,5,7,16,1,1,18,2,1,42>>).
-define(MAP_INSERT_SUBSCRIBER_DATA_REQUEST, #{cn_domain => 1,imsi => <<"262428774785152">>,message_type => isd_request,message_type_number => 16,msisdn => <<"491613460612">>,pdp_info_list => [#{access_point_name => <<1,42>>,pdp_context_id => 1}]}).

-define(BINARY_MO_FORWARD_SM_REQUEST, <<0,44,238,5,36,1,8,98,66,2,0,0,0,128,248,64,1,66,65,5,3,0,137,103,245,66,8,2,6,148,33,3,0,0,136,67,10,5,35,5,0,33,67,245,0,0,0>>).
-define(MAP_MO_FORWARD_SM_REQUEST, #{imsi => <<"262420000000088">>,message_type => mo_forward_request,message_type_number => 36,sm_rp_da => #{address => <<"98765">>,type => smsc},sm_rp_mr => 66,sm_rp_oa => #{address => <<"491230000088">>,type => msisdn},sm_rp_ui => <<5,35,5,0,33,67,245,0,0,0>>}).

-define(BINARY_SUPPLEMENTARY_SERVICE_REQUEST, <<0,44,238,5,32,1,8,98,66,2,0,0,0,64,246,48,4,32,0,0,1,49,1,1,53,21,161,19,2,1,5,2,1,59,48,11,4,1,15,4,6,170,81,12,6,27,1>>).
-define(MAP_SUPPLEMENTARY_SERVICE_REQUEST, #{imsi => <<"262420000000046">>,message_type => ss_request,message_type_number => 32,session_id => 536870913,session_state => 1,ss_info => <<161,19,2,1,5,2,1,59,48,11,4,1,15,4,6,170,81,12,6,27,1>>}).

-define(BINARY_SEND_AUTH_INFO_RESULT,<<0,192,238,5,10,1,8,98,66,2,80,118,115,7,240,3,34,32,16,251, 173,219,197,60,132,202,24,53,87,236,186,86,175,231,59,33,4, 61,86,38,102,34,8,224,104,249,198,53,145,182,54,3,34,32,16, 115,152,209,15,231,72,227,254,143,199,185,130,91,206,171, 41,33,4,236,133,225,34,34,8,67,180,13,145,7,174,211,12,3, 34,32,16,247,184,92,22,164,154,219,122,73,61,217,228,64,22, 207,229,33,4,12,236,133,61,34,8,2,247,249,165,41,173,134, 71,3,34,32,16,98,45,225,235,92,202,105,88,14,17,66,100,38, 60,70,60,33,4,125,216,104,213,34,8,92,188,236,132,7,137, 137,207,3,34,32,16,139,144,41,228,197,232,161,115,52,229, 66,150,129,111,14,163,33,4,154,221,96,95,34,8,214,95,14, 186,82,93,186,131>>).
-define(MAP_SEND_AUTH_INFO_RESULT, #{auth_tuples => [#{kc => 16170449091771348534,rand => 334538951772921257466553732075468351291,sres => 1029056102},#{kc => 4878539212899406604,rand => 153654688921371376697326139997978274601,sres => 3968196898},#{kc => 213913995087545927,rand => 329276565356490492799345768940241866725,sres => 216827197},#{kc => 6682475998917265871,rand => 130502579135052156657755432460855559740,sres => 2111334613},#{kc => 15447081440312670851,rand => 185511231865796904634040334886313594531,sres => 2598199391}],imsi => <<"262420056737700">>,message_type => sai_result,message_type_number => 10}).

%% =============================================================================
%% TESTS DESCRIPTIONS
%% =============================================================================

gsup_test_() ->
  [
    {"Check insert subscriber data request",
      ?setup(fun check_insert_subscriber_data_request/1)},

    {"Check mo-forwardSM request",
      ?setup(fun check_mo_forward_sm_request/1)},

    {"Check supplementary service request",
      ?setup(fun check_supplementary_service_request/1)},

    {"Check send auth info result",
      ?setup(fun check_send_auth_info_result/1)}
  ].

%% =============================================================================
%% SETUP FUNCTIONS
%% =============================================================================

start() ->
  application:ensure_all_started(lager).

stop(_) ->
  ok.

%% =============================================================================
%% ACTUAL TESTS
%% =============================================================================

check_insert_subscriber_data_request(_Pid) ->
  Map = gsup_encoder:encode(?MAP_INSERT_SUBSCRIBER_DATA_REQUEST),
  [?_assertEqual({?BINARY_INSERT_SUBSCRIBER_DATA_REQUEST, []}, Map)].

check_mo_forward_sm_request(_Pid) ->
  Map = gsup_encoder:encode(?MAP_MO_FORWARD_SM_REQUEST),
  [?_assertEqual({?BINARY_MO_FORWARD_SM_REQUEST, []}, Map)].

check_supplementary_service_request(_Pid) ->
  Map = gsup_encoder:encode(?MAP_SUPPLEMENTARY_SERVICE_REQUEST),
  [?_assertEqual({?BINARY_SUPPLEMENTARY_SERVICE_REQUEST, []}, Map)].

check_send_auth_info_result(_Pid) ->
  Map = gsup_encoder:encode(?MAP_SEND_AUTH_INFO_RESULT),
  [?_assertEqual({?BINARY_SEND_AUTH_INFO_RESULT, []}, Map)].
