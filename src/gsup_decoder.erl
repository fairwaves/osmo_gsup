%%%-------------------------------------------------------------------
%% @doc gsup decoder public API
%% @end
%%%-------------------------------------------------------------------

-module(gsup_decoder).

-include("../include/gsup.hrl").

%% API
-export([
  check_type/1,
  decode/1,

  % call continuation
  decode_gsup_msg/2,
  decode_gsup_auth_tuple_msg/2,
  decode_gsup_pdp_info_msg/2,
  decode_gsup_msgs/5,
  decode_imsi/1
]).

%%====================================================================
%% API
%%====================================================================

check_type(<<?OSMO_EXT, ?GSUP>>) -> true;
check_type(_BinaryType) -> false.

decode(<<MessageTypeNumber, Payload/binary>>) ->
  case known_messages() of
    #{MessageTypeNumber := #{message_type := MessageType, text := Text, mandatory := Mandatory}} ->
      {Msgs, Errors} = decode_gsup_msg(Payload, #{message_type_number => MessageTypeNumber, message_type => MessageType}),
      case maps:size(maps:with(Mandatory, Msgs)) =:= length(Mandatory) of
        true ->
          lager:info("Decoder ~s: ~p", [Text, Msgs]),
          {Msgs, Errors};
        false ->
          {false, [{miss_mandatory_msgs, Text, Mandatory} | Errors]}
      end;
    _ ->
      {false, [{invalid_message_type_number, MessageTypeNumber}]}
  end.

%%====================================================================
%% Internal functions
%%====================================================================

known_messages() ->
  #{
    16#04 => #{message_type => lu_request, text => "Location Update request", mandatory => [?IMSI]},
    16#05 => #{message_type => lu_error, text => "Location Update error", mandatory => [?IMSI, ?CAUSE]},
    16#06 => #{message_type => lu_result, text => "Location Update result", mandatory => [?IMSI]},
    % 16#06 => #{message_type => lu_result, text => "Location Update result", mandatory => [?IMSI, ?PDP_INFO]},
    16#08 => #{message_type => sai_request, text => "Send Authentication Info request", mandatory => [?IMSI]},
    16#09 => #{message_type => sai_error, text => "Send Authentication Info error", mandatory => [?IMSI, ?CAUSE]},
    16#0a => #{message_type => sai_result, text => "Send Authentication Info result", mandatory => [?IMSI]},
    16#0b => #{message_type => af_report, text => "Authentication Failure report", mandatory => [?IMSI]},
    16#0c => #{message_type => purge_ms_request, text => "Purge MS request", mandatory => [?IMSI, ?HLR_NUMBER]},
    16#0d => #{message_type => purge_ms_error, text => "Purge MS error", mandatory => [?IMSI, ?CAUSE]},
    16#0e => #{message_type => purge_ms_result, text => "Purge MS result", mandatory => [?IMSI]},
    16#10 => #{message_type => isd_request, text => "Insert Subscriber Data request", mandatory => [?IMSI]},
    16#11 => #{message_type => isd_error, text => "Insert Subscriber Data error", mandatory => [?IMSI, ?CAUSE]},
    16#12 => #{message_type => isd_result, text => "Insert Subscriber Data result", mandatory => [?IMSI]},
    16#14 => #{message_type => dsd_request, text => "Delete Subscriber Data request", mandatory => [?IMSI]},
    16#15 => #{message_type => dsd_error, text => "Delete Subscriber Data error", mandatory => [?IMSI, ?CAUSE]},
    16#16 => #{message_type => dsd_result, text => "Delete Subscriber Data result", mandatory => [?IMSI]},
    16#1c => #{message_type => lc_request, text => "Location Cancellation request", mandatory => [?IMSI]},
    16#1d => #{message_type => lc_error, text => "Location Cancellation error", mandatory => [?IMSI, ?CAUSE]},
    16#1e => #{message_type => lc_result, text => "Location Cancellation result", mandatory => [?IMSI]},
    16#20 => #{message_type => ss_request, text => "Supplementary Service request", mandatory => [?IMSI, ?SESSION_ID, ?SESSION_STATE]},
    16#21 => #{message_type => ss_error, text => "Supplementary Service error", mandatory => [?IMSI, ?SESSION_ID, ?SESSION_STATE, ?CAUSE]},
    16#22 => #{message_type => ss_result, text => "Supplementary Service result", mandatory => [?IMSI, ?SESSION_ID, ?SESSION_STATE]},
    16#24 => #{message_type => mo_forward_request, text => "MO forward request", mandatory => [?IMSI, ?SM_RP_MR, ?SM_RP_DA, ?SM_RP_OA, ?SM_RP_UI]},
    16#25 => #{message_type => mo_forward_error, text => "MO forward error", mandatory => [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE]},
    16#26 => #{message_type => mo_forward_result, text => "MO forward result", mandatory => [?SM_RP_MR, ?IMSI]},
    16#28 => #{message_type => mt_forward_request, text => "MT forward request", mandatory => [?SM_RP_MR, ?IMSI, ?SM_RP_DA, ?SM_RP_OA, ?SM_RP_UI]},
    16#29 => #{message_type => mt_forward_error, text => "MT forward error", mandatory => [?SM_RP_MR, ?IMSI, ?SM_RP_CAUSE]},
    16#2a => #{message_type => mt_forward_result, text => "MT forward result", mandatory => [?SM_RP_MR, ?IMSI]},
    16#2c => #{message_type => ready_for_sm_request, text => "Ready for SM request", mandatory => [?IMSI, ?SM_RP_MR, ?SM_ALERT_REASON]},
    16#2d => #{message_type => ready_for_sm_error, text => "Ready for SM error", mandatory => [?IMSI, ?SM_RP_MR, ?SM_RP_CAUSE]},
    16#2e => #{message_type => ready_for_sm_result, text => "Ready for SM result", mandatory => [?IMSI, ?SM_RP_MR]},
    16#30 => #{message_type => ci_request, text => "Check IMEI request", mandatory => [?IMSI, ?IMEI]},
    16#31 => #{message_type => ci_error, text => "Check IMEI error", mandatory => [?IMSI, ?CAUSE]},
    16#32 => #{message_type => ci_result, text => "Check IMEI result", mandatory => [?IMSI, ?IMEI_RESULT]}
  }.

decode_gsup_msg(<<?IMSI_HEX, Length, Imsi:Length/binary, Payload/binary>>, Map) ->
  add_to_map(decode_imsi(Imsi, <<>>), Payload, Map, ?IMSI, decode_gsup_msg);
decode_gsup_msg(<<?CAUSE_HEX, Length, Cause:Length/unit:8, Payload/binary>>, Map) ->
  add_to_map(Cause, Payload, Map, ?CAUSE, decode_gsup_msg);
decode_gsup_msg(<<?AUTH_TUPLE_HEX, Length, AuthTuple:Length/binary, Payload/binary>>, Map) ->
  decode_gsup_msgs(AuthTuple, Payload, Map, decode_gsup_auth_tuple_msg, ?AUTH_TUPLE);
decode_gsup_msg(<<?PDP_INFO_COMPLETE_HEX, ?PDP_INFO_COMPLETE_LENGTH, Payload/binary>>, Map) ->
  add_to_map(<<>>, Payload, Map, ?PDP_INFO_COMPLETE, decode_gsup_msg);
decode_gsup_msg(<<?PDP_INFO_HEX, Length, PdpInfo:Length/binary, Payload/binary>>, Map) ->
  decode_gsup_msgs(PdpInfo, Payload, Map, decode_gsup_pdp_info_msg, ?PDP_INFO);
decode_gsup_msg(<<?CANCELLATION_TYPE_HEX, ?CANCELLATION_TYPE_LENGTH, CancellType:?CANCELLATION_TYPE_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(CancellType, Payload, Map, ?CANCELLATION_TYPE, decode_gsup_msg);
decode_gsup_msg(<<?FREEZE_P_TMSI_HEX, ?FREEZE_P_TMSI_LENGTH, Payload/binary>>, Map) ->
  add_to_map(<<>>, Payload, Map, ?FREEZE_P_TMSI, decode_gsup_msg);
decode_gsup_msg(<<?MSISDN_HEX, Length, Msisdn:Length/binary, Payload/binary>>, Map) ->
  add_to_map(decode_msisdn(Msisdn, <<>>), Payload, Map, ?MSISDN, decode_gsup_msg);
decode_gsup_msg(<<?HLR_NUMBER_HEX, Length, HlrNumber:Length/binary, Payload/binary>>, Map) ->
  add_to_map(decode_msisdn(HlrNumber, <<>>), Payload, Map, ?HLR_NUMBER, decode_gsup_msg);
decode_gsup_msg(<<?PDP_CONTEXT_ID_HEX, ?PDP_CONTEXT_ID_LENGTH, PdpContextId:?PDP_CONTEXT_ID_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(PdpContextId, Payload, Map, ?PDP_CONTEXT_ID, decode_gsup_msg);
decode_gsup_msg(<<?PDP_CHARGING_HEX, ?PDP_CHARGING_LENGTH, PdpCharging:?PDP_CHARGING_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(PdpCharging, Payload, Map, ?PDP_CHARGING, decode_gsup_msg);
decode_gsup_msg(<<?AUTS_HEX, ?AUTS_LENGTH, Auts:?AUTS_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Auts, Payload, Map, ?AUTS, decode_gsup_msg);
decode_gsup_msg(<<?RAND_HEX, ?RAND_LENGTH, Rand:?RAND_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Rand, Payload, Map, ?RAND, decode_gsup_msg);
decode_gsup_msg(<<?CN_DOMAIN_HEX, ?CN_DOMAIN_LENGTH, CnDomain:?CN_DOMAIN_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(CnDomain, Payload, Map, ?CN_DOMAIN, decode_gsup_msg);
decode_gsup_msg(<<?SESSION_ID_HEX, ?SESSION_ID_LENGTH, SessionId:?SESSION_ID_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(SessionId, Payload, Map, ?SESSION_ID, decode_gsup_msg);
decode_gsup_msg(<<?SESSION_STATE_HEX, ?SESSION_STATE_LENGTH, SessionState:?SESSION_STATE_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(SessionState, Payload, Map, ?SESSION_STATE, decode_gsup_msg);
decode_gsup_msg(<<?SS_INFO_HEX, Length, SupplementaryServiceInfo:Length/binary, Payload/binary>>, Map) ->
  add_to_map(SupplementaryServiceInfo, Payload, Map, ?SS_INFO, decode_gsup_msg);
decode_gsup_msg(<<?SM_RP_MR_HEX, ?SM_RP_MR_LENGTH, SmRpMr:?SM_RP_MR_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(SmRpMr, Payload, Map, ?SM_RP_MR, decode_gsup_msg);
decode_gsup_msg(<<?SM_RP_DA_HEX, Length, SmRpDa:Length/binary, Payload/binary>>, Map) ->
  add_to_map(decode_address(SmRpDa, <<>>), Payload, Map, ?SM_RP_DA, decode_gsup_msg);
decode_gsup_msg(<<?SM_RP_OA_HEX, Length, SmRpOa:Length/binary, Payload/binary>>, Map) ->
  add_to_map(decode_address(SmRpOa, <<>>), Payload, Map, ?SM_RP_OA, decode_gsup_msg);
decode_gsup_msg(<<?SM_RP_UI_HEX, Length, SmRpUi:Length/binary, Payload/binary>>, Map) ->
  add_to_map(SmRpUi, Payload, Map, ?SM_RP_UI, decode_gsup_msg);
decode_gsup_msg(<<?SM_RP_CAUSE_HEX, Length, SmRpCause:Length/unit:8, Payload/binary>>, Map) ->
  add_to_map(SmRpCause, Payload, Map, ?SM_RP_CAUSE, decode_gsup_msg);
decode_gsup_msg(<<?SM_RP_MMS_HEX, ?SM_RP_MMS_LENGTH, SmRpMms:?SM_RP_MMS_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(SmRpMms, Payload, Map, ?SM_RP_MMS, decode_gsup_msg);
decode_gsup_msg(<<?SM_ALERT_REASON_HEX, Length, SmAlertReason:Length/binary, Payload/binary>>, Map) ->
  add_to_map(SmAlertReason, Payload, Map, ?SM_ALERT_REASON, decode_gsup_msg);
decode_gsup_msg(<<?IMEI_HEX, Length, Imei:Length/binary, Payload/binary>>, Map) ->
  add_to_map(decode_imsi(Imei, <<>>), Payload, Map, ?IMEI, decode_gsup_msg);
decode_gsup_msg(<<?IMEI_RESULT_HEX, ?IMEI_RESULT_LENGTH, ImeiResult:?IMEI_RESULT_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(ImeiResult, Payload, Map, ?IMEI_RESULT, decode_gsup_msg);
decode_gsup_msg(<<>>, Map) ->
  {Map, []};
decode_gsup_msg(Payload, Map) ->
  {Map, [{invalid_Msg, Payload}]}.

decode_gsup_msgs(Msg, Payload, Map, CallContinuation, TypeMsg) ->
  MsgMaps = maps:get(TypeMsg, Map, []),
  {MsgMap, Errors} = gsup_decoder:CallContinuation(Msg, maps:new()),
  case Errors of
    [] ->
      NewMsgMaps = [MsgMap | MsgMaps],
      NewMap = maps:put(TypeMsg, NewMsgMaps, Map),
      decode_gsup_msg(Payload, NewMap);
    _ ->
      {Map, Errors}
  end.

decode_gsup_auth_tuple_msg(<<?RAND_HEX, ?RAND_LENGTH, Rand:?RAND_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Rand, Payload, Map, ?RAND, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<?SRES_HEX, ?SRES_LENGTH, Sres:?SRES_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Sres, Payload, Map, ?SRES, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<?KC_HEX, ?KC_LENGTH, Kc:?KC_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Kc, Payload, Map, ?KC, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<?IK_HEX, ?IK_LENGTH, Ik:?IK_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Ik, Payload, Map, ?IK, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<?CK_HEX, ?CK_LENGTH, Ck:?CK_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Ck, Payload, Map, ?CK, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<?AUTN_HEX, ?AUTN_LENGTH, Autn:?AUTN_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(Autn, Payload, Map, ?AUTN, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<?RES_HEX, Length, Res:Length/binary, Payload/binary>>, Map) ->
  add_to_map(Res, Payload, Map, ?RES, decode_gsup_auth_tuple_msg);
decode_gsup_auth_tuple_msg(<<>>, Map) ->
  {Map, []};
decode_gsup_auth_tuple_msg(Payload, Map) ->
  {Map, [{invalid_auth_tuple_msg, Payload}]}.

decode_gsup_pdp_info_msg(<<?PDP_CONTEXT_ID_HEX, ?PDP_CONTEXT_ID_LENGTH, PdpContextId:?PDP_CONTEXT_ID_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(PdpContextId, Payload, Map, ?PDP_CONTEXT_ID, decode_gsup_pdp_info_msg);
decode_gsup_pdp_info_msg(<<?PDP_TYPE_HEX, ?PDP_TYPE_LENGTH, PdpType:?PDP_TYPE_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(decode_pdp_type(PdpType), Payload, Map, ?PDP_TYPE, decode_gsup_pdp_info_msg);
decode_gsup_pdp_info_msg(<<?ACCESS_POINT_NAME_HEX, Length, AccessPointName:Length/binary, Payload/binary>>, Map) ->
  add_to_map(AccessPointName, Payload, Map, ?ACCESS_POINT_NAME, decode_gsup_pdp_info_msg);
decode_gsup_pdp_info_msg(<<?QUALITY_OF_SERVICE_HEX, Length, QualityOfService:Length/binary, Payload/binary>>, Map) ->
  add_to_map(QualityOfService, Payload, Map, ?QUALITY_OF_SERVICE, decode_gsup_pdp_info_msg);
decode_gsup_pdp_info_msg(<<?PDP_CHARGING_HEX, ?PDP_CHARGING_LENGTH, PdpCharging:?PDP_CHARGING_LENGTH/unit:8, Payload/binary>>, Map) ->
  add_to_map(PdpCharging, Payload, Map, pdp_charging_characteristics, decode_gsup_pdp_info_msg);
decode_gsup_pdp_info_msg(<<>>, Map) ->
  {Map, []};
decode_gsup_pdp_info_msg(Payload, Map) ->
  {Map, [{invalid_pdp_info_msg, Payload}]}.

decode_address(<<AddressType, Address/binary>>, Buffer) ->
  Type = get_address_type(AddressType),
  case Type of
    imsi -> #{type => Type, address => decode_imsi(Address, Buffer)};
    msisdn -> #{type => Type, address => decode_msisdn(Address, Buffer)};
    smsc -> #{type => Type, address => decode_msisdn(Address, Buffer)};
    omit -> #{type => Type}
  end.

decode_msisdn(<<_IgnoredByte, Data/binary>>, Buffer) -> decode_imsi(Data, Buffer).

get_address_type(1) -> imsi;
get_address_type(2) -> msisdn;
get_address_type(3) -> smsc;
get_address_type(16#ff) -> omit.

decode_imsi(<<>>, Buffer) -> Buffer;
decode_imsi(<<DigitOne:4, DigitTwo:4, Tail/binary>>, Buffer) when DigitOne < 10, DigitTwo < 10 ->
  decode_imsi(Tail, <<Buffer/binary, ($0 + DigitTwo), ($0 + DigitOne)>>);
decode_imsi(<<_:4, DigitTwo:4, _Tail/binary>>, Buffer) when DigitTwo < 10 ->
  <<Buffer/binary, ($0 + DigitTwo)>>.

decode_pdp_type(<<Spare:4, PdpTypeOrg:4, PdpTypeNumber>>) ->
  #{spare => Spare, pdp_type_org => PdpTypeOrg, pdp_type_number => PdpTypeNumber}.

add_to_map(Msg, Payload, Map, TypeMsg, CallContinuation) ->
  case maps:is_key(TypeMsg, Map) of
    false ->
      NewMap = maps:put(TypeMsg, Msg, Map),
      gsup_decoder:CallContinuation(Payload, NewMap);
    _ ->
      {Map, [{repeat_msg, TypeMsg}]}
  end.

decode_imsi(IMSI) -> decode_imsi(IMSI, <<>>).
