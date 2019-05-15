%%%-------------------------------------------------------------------
%% @doc gsup encoder public API
%% @end
%%%-------------------------------------------------------------------

-module(gsup_encoder).

-include("../include/gsup.hrl").

%% API
-export([
  encode/1
]).

%%====================================================================
%% API
%%====================================================================

encode(#{message_type := MessageType} = Map) ->
  case known_messages() of
    #{MessageType := #{message_type_number := MessageTypeNumber, text := Text, mandatory := Mandatory}} ->
      case maps:size(maps:with(Mandatory, Map)) =:= length(Mandatory) of
        true ->
          lager:info("Encoder ~s: ~p", [Text, Map]),
          {Payload, Errors} = encode_gsup_map(maps:without([message_type], Map), get_data_order(MessageType), <<>>),
          Length = erlang:size(Payload) + 2,
          {<<Length:16, ?OSMO_EXT, ?GSUP, MessageTypeNumber, Payload/binary>>, Errors};
        false ->
          {false, [{miss_mandatory_params, Text, Mandatory}]}
      end;
    _ ->
      {false, [{invalid_message_type, MessageType}]}
  end.

%%====================================================================
%% Internal functions
%%====================================================================

known_messages() ->
  #{
    lu_request => #{message_type_number => 16#04, text => "Location Update request", mandatory => [?IMSI]},
    lu_error => #{message_type_number => 16#05, text => "Location Update error", mandatory => [?IMSI, ?CAUSE]},
    lu_result => #{message_type_number => 16#06, text => "Location Update result", mandatory => [?IMSI]},
    % lu_result => #{message_type_number => 16#06, text => "Location Update result", mandatory => [?IMSI, ?PDP_INFO]},
    sai_request => #{message_type_number => 16#08, text => "Send Authentication Info request", mandatory => [?IMSI]},
    sai_error => #{message_type_number => 16#09, text => "Send Authentication Info error", mandatory => [?IMSI, ?CAUSE]},
    sai_result => #{message_type_number => 16#0a, text => "Send Authentication Info result", mandatory => [?IMSI]},
    af_report => #{message_type_number => 16#0b, text => "Authentication Failure report", mandatory => [?IMSI]},
    purge_ms_request => #{message_type_number => 16#0c, text => "Purge MS request", mandatory => [?IMSI, ?HLR_NUMBER]},
    purge_ms_error => #{message_type_number => 16#0d, text => "Purge MS error", mandatory => [?IMSI, ?CAUSE]},
    purge_ms_result => #{message_type_number => 16#0e, text => "Purge MS result", mandatory => [?IMSI]},
    isd_request => #{message_type_number => 16#10, text => "Insert Subscriber Data request", mandatory => [?IMSI]},
    isd_error => #{message_type_number => 16#11, text => "Insert Subscriber Data error", mandatory => [?IMSI, ?CAUSE]},
    isd_result => #{message_type_number => 16#12, text => "Insert Subscriber Data result", mandatory => [?IMSI]},
    dsd_request => #{message_type_number => 16#14, text => "Delete Subscriber Data request", mandatory => [?IMSI]},
    dsd_error => #{message_type_number => 16#15, text => "Delete Subscriber Data error", mandatory => [?IMSI, ?CAUSE]},
    dsd_result => #{message_type_number => 16#16, text => "Delete Subscriber Data result", mandatory => [?IMSI]},
    lc_request => #{message_type_number => 16#1c, text => "Location Cancellation request", mandatory => [?IMSI]},
    lc_error => #{message_type_number => 16#1d, text => "Location Cancellation error", mandatory => [?IMSI, ?CAUSE]},
    lc_result => #{message_type_number => 16#1e, text => "Location Cancellation result", mandatory => [?IMSI]},
    ss_request => #{message_type_number => 16#20, text => "Supplementary Service request", mandatory => [?IMSI, ?SESSION_ID, ?SESSION_STATE]},
    ss_error => #{message_type_number => 16#21, text => "Supplementary Service error", mandatory => [?IMSI, ?SESSION_ID, ?SESSION_STATE, ?CAUSE]},
    ss_result => #{message_type_number => 16#22, text => "Supplementary Service result", mandatory => [?IMSI, ?SESSION_ID, ?SESSION_STATE]},
    mo_forward_request => #{message_type_number => 16#24, text => "MO forward request", mandatory => [
      ?IMSI, ?SM_RP_MR, ?SM_RP_DA, ?SM_RP_OA, ?SM_RP_UI]
    },
    mo_forward_error => #{message_type_number => 16#25, text => "MO forward error", mandatory => [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE]},
    mo_forward_result => #{message_type_number => 16#26, text => "MO forward result", mandatory => [?SM_RP_MR, ?IMSI]},
    mt_forward_request => #{message_type_number => 16#28, text => "MT forward request", mandatory => [
      ?SM_RP_MR, ?IMSI, ?SM_RP_DA, ?SM_RP_OA, ?SM_RP_UI]
    },
    mt_forward_error => #{message_type_number => 16#29, text => "MT forward error", mandatory => [?SM_RP_MR, ?IMSI, ?SM_RP_CAUSE]},
    mt_forward_result => #{message_type_number => 16#2a, text => "MT forward result", mandatory => [?SM_RP_MR, ?IMSI]},
    ready_for_sm_request => #{message_type => 16#2c, text => "Ready for SM request", mandatory => [?IMSI, ?SM_RP_MR, ?SM_ALERT_REASON]},
    ready_for_sm_error => #{message_type_number => 16#2d, text => "Ready for SM error", mandatory => [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE]},
    ready_for_sm_result => #{message_type_number => 16#2e, text => "Ready for SM result", mandatory => [?IMSI, ?SM_RP_MR]},
    ci_request => #{message_type_number => 16#30, text => "Check IMEI request", mandatory => [?IMSI, ?IMEI]},
    ci_error => #{message_type_number => 16#31, text => "Check IMEI error", mandatory => [?IMSI, ?CAUSE]},
    ci_result => #{message_type_number => 16#32, text => "Check IMEI result", mandatory => [?IMSI, ?IMEI_RESULT]}
  }.

get_data_order(lu_request) -> [?IMSI, ?CN_DOMAIN, ?CANCELLATION_TYPE];
get_data_order(lu_error) -> [?IMSI, ?CAUSE];
get_data_order(lu_result) -> [?IMSI, ?MSISDN, ?HLR_NUMBER, ?PDP_INFO_COMPLETE, ?PDP_INFO];
get_data_order(sai_request) -> [?IMSI, ?CN_DOMAIN, ?AUTS, ?RAND];
get_data_order(sai_error) -> [?IMSI, ?CAUSE];
get_data_order(sai_result) -> [?IMSI, ?AUTH_TUPLE];
get_data_order(af_report) -> [?IMSI, ?CN_DOMAIN];
get_data_order(purge_ms_request) -> [?IMSI, ?CN_DOMAIN, ?HLR_NUMBER];
get_data_order(purge_ms_error) -> [?IMSI, ?CAUSE];
get_data_order(purge_ms_result) -> [?IMSI, ?FREEZE_P_TMSI];
get_data_order(isd_request) -> [?IMSI, ?CN_DOMAIN, ?MSISDN, ?HLR_NUMBER, ?PDP_INFO_COMPLETE, ?PDP_INFO, ?PDP_CHARGING];
get_data_order(isd_error) -> [?IMSI, ?CAUSE];
get_data_order(isd_result) -> [?IMSI];
get_data_order(dsd_request) -> [?IMSI, ?CN_DOMAIN, ?PDP_CONTEXT_ID];
get_data_order(dsd_error) -> [?IMSI, ?CAUSE];
get_data_order(dsd_result) -> [?IMSI];
get_data_order(lc_request) -> [?IMSI, ?CAUSE];
get_data_order(lc_error) -> [?IMSI, ?CAUSE];
get_data_order(lc_result) -> [?IMSI, ?CN_DOMAIN];
get_data_order(ss_request) -> [?IMSI, ?SESSION_ID, ?SESSION_STATE, ?SS_INFO];
get_data_order(ss_error) -> [?IMSI, ?SESSION_ID, ?SESSION_STATE, ?CAUSE];
get_data_order(ss_result) -> [?IMSI, ?SESSION_ID, ?SESSION_STATE, ?SS_INFO];
get_data_order(mo_forward_request) -> [?IMSI, ?SM_RP_MR, ?SM_RP_DA, ?SM_RP_OA, ?SM_RP_UI];
get_data_order(mo_forward_error) -> [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE, ?SM_RP_UI];
get_data_order(mo_forward_result) -> [?IMSI, ?SM_RP_MR];
get_data_order(mt_forward_request) -> [?IMSI, ?SM_RP_MR, ?SM_RP_DA, ?SM_RP_OA, ?SM_RP_UI, ?SM_RP_MMS];
get_data_order(mt_forward_error) -> [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE, ?SM_RP_UI];
get_data_order(mt_forward_result) -> [?IMSI, ?SM_RP_MR];
get_data_order(ready_for_sm_request) -> [?IMSI, ?SM_RP_MR, ?SM_ALERT_REASON];
get_data_order(ready_for_sm_error) -> [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE, ?SM_RP_UI];
get_data_order(ready_for_sm_result) -> [?IMSI, ?SM_RP_MR];
get_data_order(ci_request) -> [?IMSI, ?IMEI];
get_data_order(ci_error) -> [?IMSI, ?CAUSE];
get_data_order(ci_result) -> [?IMSI, ?IMEI_RESULT].

encode_gsup_map(#{?IMSI := Imsi} = Map, [?IMSI | OrderList], Buffer) ->
  add_imsi_to_binary_buffer(?IMSI, ?IMSI_HEX, Imsi, Map, OrderList, Buffer);
encode_gsup_map(#{?CN_DOMAIN := CnDomain} = Map, [?CN_DOMAIN | OrderList], Buffer) ->
  add_to_binary_buffer(?CN_DOMAIN, ?CN_DOMAIN_HEX, CnDomain, Map, OrderList, Buffer);
encode_gsup_map(#{?CANCELLATION_TYPE := CancellationType} = Map, [?CANCELLATION_TYPE | OrderList], Buffer) ->
  add_to_binary_buffer(?CANCELLATION_TYPE, ?CANCELLATION_TYPE_HEX, CancellationType, Map, OrderList, Buffer);
encode_gsup_map(#{?CAUSE := Cause} = Map, [?CAUSE | OrderList], Buffer) ->
  add_to_binary_buffer(?CAUSE, ?CAUSE_HEX, Cause, Map, OrderList, Buffer);
encode_gsup_map(#{?MSISDN := Msisdn} = Map, [?MSISDN | OrderList], Buffer) ->
  add_msisdn_to_binary_buffer(?MSISDN, ?MSISDN_HEX, Msisdn, Map, OrderList, Buffer);
encode_gsup_map(#{?HLR_NUMBER := HlrNumber} = Map, [?HLR_NUMBER | OrderList], Buffer) ->
  add_msisdn_to_binary_buffer(?HLR_NUMBER, ?HLR_NUMBER_HEX, HlrNumber, Map, OrderList, Buffer);
encode_gsup_map(#{?PDP_INFO_COMPLETE := PdpInfoComplete} = Map, [?PDP_INFO_COMPLETE | OrderList], Buffer) ->
  add_to_binary_buffer(?PDP_INFO_COMPLETE, ?PDP_INFO_COMPLETE_HEX, PdpInfoComplete, Map, OrderList, Buffer);
encode_gsup_map(#{?PDP_INFO := PdpInfoList} = Map, [?PDP_INFO | OrderList], Buffer) when erlang:is_list(PdpInfoList) ->
  PdpInfoOrderList = [?PDP_CONTEXT_ID, ?PDP_TYPE, ?ACCESS_POINT_NAME, ?QUALITY_OF_SERVICE, ?PDP_CHARGING],
  encode_values_map(?PDP_INFO, ?PDP_INFO_HEX, PdpInfoList, Map, OrderList, Buffer, PdpInfoOrderList);
encode_gsup_map(#{?AUTS := Auts} = Map, [?AUTS | OrderList], Buffer) ->
  add_to_binary_buffer(?AUTS, ?AUTS_HEX, Auts, Map, OrderList, Buffer);
encode_gsup_map(#{?RAND := Rand} = Map, [?RAND | OrderList], Buffer) ->
  add_to_binary_buffer(?RAND, ?RAND_HEX, Rand, Map, OrderList, Buffer);
encode_gsup_map(#{?AUTH_TUPLE := AuthTuples} = Map, [?AUTH_TUPLE | OrderList], Buffer) when erlang:is_list(AuthTuples) ->
  encode_values_map(?AUTH_TUPLE, ?AUTH_TUPLE_HEX, AuthTuples, Map, OrderList, Buffer, [?RAND, ?SRES, ?KC, ?IK, ?CK, ?AUTN, ?RES]);
encode_gsup_map(#{?FREEZE_P_TMSI := FreezePTmsi} = Map, [?FREEZE_P_TMSI | OrderList], Buffer) ->
  add_to_binary_buffer(?FREEZE_P_TMSI, ?FREEZE_P_TMSI_HEX, FreezePTmsi, Map, OrderList, Buffer);
encode_gsup_map(#{?PDP_CHARGING := PdpCharging} = Map, [?PDP_CHARGING | OrderList], Buffer) ->
  add_to_binary_buffer(?PDP_CHARGING, ?PDP_CHARGING_HEX, PdpCharging, Map, OrderList, Buffer);
encode_gsup_map(#{?PDP_CONTEXT_ID := PdpContextId} = Map, [?PDP_CONTEXT_ID | OrderList], Buffer) ->
  add_to_binary_buffer(?PDP_CONTEXT_ID, ?PDP_CONTEXT_ID_HEX, PdpContextId, Map, OrderList, Buffer);
encode_gsup_map(#{?SESSION_ID := SessionId} = Map, [?SESSION_ID | OrderList], Buffer) ->
  add_to_binary_buffer(?SESSION_ID, ?SESSION_ID_HEX, SessionId, Map, OrderList, Buffer);
encode_gsup_map(#{?SESSION_STATE := SessionState} = Map, [?SESSION_STATE | OrderList], Buffer) ->
  add_to_binary_buffer(?SESSION_STATE, ?SESSION_STATE_HEX, SessionState, Map, OrderList, Buffer);
encode_gsup_map(#{?SS_INFO := SupplementaryService} = Map, [?SS_INFO | OrderList], Buffer) ->
  add_to_binary_buffer(?SS_INFO, ?SS_INFO_HEX, SupplementaryService, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_RP_MR := SmRpMr} = Map, [?SM_RP_MR | OrderList], Buffer) ->
  add_to_binary_buffer(?SM_RP_MR, ?SM_RP_MR_HEX, SmRpMr, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_RP_DA := SmRpDa} = Map, [?SM_RP_DA | OrderList], Buffer) ->
  add_address_to_binary_buffer(?SM_RP_DA, ?SM_RP_DA_HEX, SmRpDa, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_RP_OA := SmRpOa} = Map, [?SM_RP_OA | OrderList], Buffer) ->
  add_address_to_binary_buffer(?SM_RP_OA, ?SM_RP_OA_HEX, SmRpOa, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_RP_CAUSE := SmRpCause} = Map, [?SM_RP_CAUSE | OrderList], Buffer) ->
  add_to_binary_buffer(?SM_RP_CAUSE, ?SM_RP_CAUSE_HEX, SmRpCause, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_RP_UI := SmRpUi} = Map, [?SM_RP_UI | OrderList], Buffer) ->
  add_to_binary_buffer(?SM_RP_UI, ?SM_RP_UI_HEX, SmRpUi, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_RP_MMS := SmRpMms} = Map, [?SM_RP_MMS | OrderList], Buffer) ->
  add_to_binary_buffer(?SM_RP_MMS, ?SM_RP_MMS_HEX, SmRpMms, Map, OrderList, Buffer);
encode_gsup_map(#{?SM_ALERT_REASON := SmAlertReason} = Map, [?SM_ALERT_REASON | OrderList], Buffer) ->
  add_to_binary_buffer(?SM_ALERT_REASON, ?SM_ALERT_REASON_HEX, SmAlertReason, Map, OrderList, Buffer);
encode_gsup_map(#{?IMEI := Imei} = Map, [?IMEI | OrderList], Buffer) ->
  add_to_binary_buffer(?IMEI, ?IMEI_HEX, Imei, Map, OrderList, Buffer);
encode_gsup_map(#{?IMEI_RESULT := ImeiResult} = Map, [?IMEI_RESULT | OrderList], Buffer) ->
  add_to_binary_buffer(?IMEI_RESULT, ?IMEI_RESULT_HEX, ImeiResult, Map, OrderList, Buffer);
encode_gsup_map(#{?PDP_TYPE := PdpType} = Map, [?PDP_TYPE | OrderList], Buffer) ->
  add_to_binary_buffer(?PDP_TYPE, ?PDP_TYPE_HEX, PdpType, Map, OrderList, Buffer);
encode_gsup_map(#{?ACCESS_POINT_NAME := AccessPointName} = Map, [?ACCESS_POINT_NAME | OrderList], Buffer) ->
  add_to_binary_buffer(?ACCESS_POINT_NAME, ?ACCESS_POINT_NAME_HEX, AccessPointName, Map, OrderList, Buffer);
encode_gsup_map(#{?QUALITY_OF_SERVICE := QualityOfService} = Map, [?QUALITY_OF_SERVICE | OrderList], Buffer) ->
  add_to_binary_buffer(?QUALITY_OF_SERVICE, ?QUALITY_OF_SERVICE_HEX, QualityOfService, Map, OrderList, Buffer);
encode_gsup_map(#{?SRES := Sres} = Map, [?SRES | OrderList], Buffer) ->
  add_to_binary_buffer(?SRES, ?SRES_HEX, Sres, Map, OrderList, Buffer);
encode_gsup_map(#{?KC := Kc} = Map, [?KC | OrderList], Buffer) ->
  add_to_binary_buffer(?KC, ?KC_HEX, Kc, Map, OrderList, Buffer);
encode_gsup_map(#{?IK := Ik} = Map, [?IK | OrderList], Buffer) ->
  add_to_binary_buffer(?IK, ?IK_HEX, Ik, Map, OrderList, Buffer);
encode_gsup_map(#{?CK := Ck} = Map, [?CK | OrderList], Buffer) ->
  add_to_binary_buffer(?CK, ?CK_HEX, Ck, Map, OrderList, Buffer);
encode_gsup_map(#{?AUTN := Autn} = Map, [?AUTN | OrderList], Buffer) ->
  add_to_binary_buffer(?AUTN, ?AUTN_HEX, Autn, Map, OrderList, Buffer);
encode_gsup_map(#{?RES := Res} = Map, [?RES | OrderList], Buffer) ->
  add_to_binary_buffer(?RES, ?AUTN_HEX, Res, Map, OrderList, Buffer);
encode_gsup_map(Map, [_IgnoringParam | OrderList], Payload) ->
  encode_gsup_map(Map, OrderList, Payload);
encode_gsup_map(#{}, _OrderList, Payload) ->
  {Payload, []};
encode_gsup_map(Map, OrderList, Payload) ->
  {Payload, [{invalid_map, Map, OrderList}]}.

encode_values_map(KeyMap, Hex, [ValueMap | ValuesMap], Map, OrderList, Buffer, ParamOrderList) ->
  {BinParam, Errors} = encode_gsup_map(ValueMap, ParamOrderList, <<>>),
  case Errors of
    [] ->
      Length = erlang:size(BinParam),
      NewBuffer = <<Buffer/binary, Hex:8, Length, BinParam/binary>>,
      encode_values_map(KeyMap, Hex, ValuesMap, Map, OrderList, NewBuffer, ParamOrderList);
    _ ->
      {Buffer, Errors}
  end;
encode_values_map(KeyMap, _Hex, [], Map, OrderList, Buffer, _ParamOrderList) ->
  encode_gsup_map(maps:without([KeyMap], Map), OrderList, Buffer).

add_imsi_to_binary_buffer(KeyMap, Hex, Imsi, Map, OrderList, Buffer) ->
  BinImsi = get_binary_imsi(Imsi, <<>>),
  Length = erlang:size(BinImsi),
  NewMap = maps:without([KeyMap], Map),
  encode_gsup_map(NewMap, OrderList, <<Buffer/binary, Hex:8, Length, BinImsi/binary>>).

add_msisdn_to_binary_buffer(KeyMap, Hex, Msisdn, Map, OrderList, Buffer) ->
  BinMsisdn = get_binary_imsi(Msisdn, <<>>),
  Length = erlang:size(BinMsisdn) + 1,
  NewMap = maps:without([KeyMap], Map),
  encode_gsup_map(NewMap, OrderList, <<Buffer/binary, Hex:8, Length, 16#06, BinMsisdn/binary>>).

add_address_to_binary_buffer(KeyMap, Hex, Address, Map, OrderList, Buffer) ->
  BinAddress = encode_address(Address),
  Length = erlang:size(BinAddress),
  NewMap = maps:without([KeyMap], Map),
  encode_gsup_map(NewMap, OrderList, <<Buffer/binary, Hex:8, Length, BinAddress/binary>>).

add_to_binary_buffer(KeyMap, Hex, ValueMap, Map, OrderList, Buffer) ->
  BinParam = integer_param_to_binary(ValueMap),
  Length = erlang:size(BinParam),
  NewMap = maps:without([KeyMap], Map),
  encode_gsup_map(NewMap, OrderList, <<Buffer/binary, Hex:8, Length, BinParam/binary>>).

get_binary_imsi(<<DigitOne, DigitTwo, Tail/binary>>, Buffer) when DigitOne =< $9, DigitOne >= $0, DigitTwo =< $9, DigitTwo >= $0 ->
  get_binary_imsi(Tail, <<Buffer/binary, DigitTwo:4, DigitOne:4>>);
get_binary_imsi(<<DigitOne>>, Buffer) when DigitOne =< $9, DigitOne >= $0 ->
  <<Buffer/binary, 16#f:4, DigitOne:4>>;
get_binary_imsi(<<>>, Buffer) ->
  Buffer.

encode_address(#{type := imsi, address := Addr}) -> <<16#01, (get_binary_imsi(Addr, <<>>))/binary>>;
encode_address(#{type := msisdn, address := Addr}) -> <<16#02, 16#06, (get_binary_imsi(Addr, <<>>))/binary>>;
encode_address(#{type := smsc, address := Addr}) -> <<16#03, 16#00, (get_binary_imsi(Addr, <<>>))/binary>>;
encode_address(#{type := omit}) -> <<16#ff>>.

integer_param_to_binary(ValueMap) when erlang:is_binary(ValueMap) ->
  ValueMap;
integer_param_to_binary(ValueMap) when erlang:is_integer(ValueMap), ValueMap >= 0, ValueMap =< 16#ff ->
  <<ValueMap:8>>;
integer_param_to_binary(ValueMap) when erlang:is_integer(ValueMap), ValueMap >= 0, ValueMap =< 16#ffff ->
  <<ValueMap:16>>;
integer_param_to_binary(ValueMap) when erlang:is_integer(ValueMap), ValueMap >= 0, ValueMap =< 16#ffffff ->
  <<ValueMap:24>>;
integer_param_to_binary(ValueMap) when erlang:is_integer(ValueMap), ValueMap >= 0, ValueMap =< 16#ffffffff ->
  <<ValueMap:32>>;
integer_param_to_binary(ValueMap) when erlang:is_integer(ValueMap), ValueMap >= 0, ValueMap =< 16#ffffffffffffffff ->
  <<ValueMap:64>>;
integer_param_to_binary(ValueMap) when erlang:is_integer(ValueMap), ValueMap >= 0, ValueMap =< 16#ffffffffffffffffffffffffffffffff ->
  <<ValueMap:128>>.

