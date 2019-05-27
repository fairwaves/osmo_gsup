-module(gsup_protocol).

-include ("gsup_protocol.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([decode/1, encode/1, decode_bcd/1]).
-export_type(['GSUPMessage'/0, 'GSUPMessageType'/0]).

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


-spec decode(binary()) -> {ok, {'GSUPMessage'(), binary()}} | {more_data, binary()} | {error, term()}.
decode(<<PSize:16, 16#ee, Packet:PSize/binary, Rest/binary>>) ->
  <<16#05, MsgNum, Tail/binary>> = Packet,
  Messages = gsup_messages(),
  GSUPMessage = decode_ie(Tail, #{}),
  case Messages of
    #{MsgNum := #{message_type := Msg, mandatory := Mandatory, possible := Possible}} ->
      case {maps:size(maps:with(Mandatory, GSUPMessage)) == length(Mandatory), maps:size(maps:without(Possible ++ [message_type], GSUPMessage)) == 0} of
        {true, true} -> {ok, {GSUPMessage#{message_type => Msg}, Rest}};
        {false, _} -> {error, {ie_missing, Mandatory -- maps:keys(GSUPMessage)}};
        {_, false} -> {error, {ie_not_expected, maps:keys(GSUPMessage) -- Possible}}
      end;
    _ -> 
      {error, {unknown_message, MsgNum, GSUPMessage}}
  end;

decode(<<_PSize:16, X, _/binary>> = Rest) when X /= 16#ee ->
  {error, {bad_packet, Rest}};

decode(Rest) ->
  {more_data, Rest}.

decode_ie(<<>>, Map) -> Map;

decode_ie(<<?IMSI_HEX, Len, IMSI:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{imsi => decode_bcd(IMSI, <<>>)});

decode_ie(<<?CAUSE_HEX, Len, Cause:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{cause => Cause});

decode_ie(<<?AUTH_TUPLE_HEX, Len, AuthTuple0:Len/binary, Tail/binary>>, Map) ->
  List = maps:get(auth_tuples, Map, []),
  AuthTuple = decode_auth_tuple(AuthTuple0, #{}),
  true = check_auth_tuple(AuthTuple),
  decode_ie(Tail, Map#{auth_tuples => List ++ [AuthTuple]});

decode_ie(<<?PDP_INFO_COMPLETE_HEX, 0, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{pdp_info_complete => <<>>});

decode_ie(<<?PDP_INFO_HEX, Len, PDPInfo0:Len/binary, Tail/binary>>, Map) ->
  List = maps:get(pdp_info_list, Map, []),
  PDPInfo = decode_pdp_info(PDPInfo0, #{}),
  true = check_pdp_info(PDPInfo),
  decode_ie(Tail, Map#{pdp_info_list => List ++ [PDPInfo]});

decode_ie(<<?CANCELLATION_TYPE_HEX, Len, CancellationType:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{cancellation_type => CancellationType});

decode_ie(<<?FREEZE_P_TMSI_HEX, Len, FreezePTMSI:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{freeze_p_tmsi => FreezePTMSI});

decode_ie(<<?MSISDN_HEX, Len, MSISDN:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{msisdn => decode_msisdn(MSISDN, <<>>)});

decode_ie(<<?HLR_NUMBER_HEX, Len, HLRNumber:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{hlr_number => decode_msisdn(HLRNumber, <<>>)});

decode_ie(<<?PDP_CONTEXT_ID_HEX, Len, PDPContextId:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{pdp_context_id => PDPContextId});

decode_ie(<<?PDP_CHARGING_HEX, Len, PDPCharging:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{pdp_charging => PDPCharging});

decode_ie(<<?RAND_HEX, Len, Rand:Len/unit:8, Tail/binary>>, Map) when Len == 16->
  decode_ie(Tail, Map#{rand => Rand});

decode_ie(<<?AUTS_HEX, Len, AUTS:Len/unit:8, Tail/binary>>, Map) when Len == 14 ->
  decode_ie(Tail, Map#{auts => AUTS});

decode_ie(<<?CN_DOMAIN_HEX, Len, CN_Domain:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{cn_domain => CN_Domain});

decode_ie(<<?SESSION_ID_HEX, Len, SesID:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{session_id => SesID});

decode_ie(<<?SESSION_STATE_HEX, Len, SesState:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{session_state => SesState});

decode_ie(<<?SS_INFO_HEX, Len, SesInfo:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{ss_info => SesInfo});

decode_ie(<<?SM_RP_MR_HEX, Len, MsgRef:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_mr => MsgRef});

decode_ie(<<?SM_RP_DA_HEX, Len, DA:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_da => decode_oa_da(DA, <<>>)});

decode_ie(<<?SM_RP_OA_HEX, Len, OA:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_oa => decode_oa_da(OA, <<>>)});

decode_ie(<<?SM_RP_UI_HEX, Len, MessageBody:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_ui => MessageBody});

decode_ie(<<?SM_RP_CAUSE_HEX, Len, RPCause:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_cause => RPCause});

decode_ie(<<?SM_RP_MMS_HEX, Len, RPMMS:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_mms => RPMMS});

decode_ie(<<?SM_ALERT_REASON_HEX, Len, AlertReason:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_alert_reason => AlertReason});

decode_ie(<<?IMEI_HEX, Len, IMEI:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{imei => IMEI});

decode_ie(<<?IMEI_CHECK_RESULT_HEX, Len, IMEIResult:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{imei_check_result => IMEIResult}).

-spec decode_bcd(binary()) -> binary().
decode_bcd(BCD) -> decode_bcd(BCD, <<>>).

decode_bcd(<<>>, Buffer) -> Buffer;

decode_bcd(<<A:4, B:4, Tail/binary>>, Buffer) when A < 10, B < 10 ->
  decode_bcd(Tail, <<Buffer/binary, ($0 + B), ($0 + A)>>);

decode_bcd(<<_:4, B:4, _Tail/binary>>, Buffer) when B < 10 ->
  <<Buffer/binary, ($0 + B)>>.

decode_msisdn(<<_X, Data/binary>>, Buffer) -> decode_bcd(Data, Buffer).

decode_oa_da(<<1, _, Addr/binary>>, Buffer) -> {imsi, decode_bcd(Addr, Buffer)};

decode_oa_da(<<2, _, Addr/binary>>, Buffer) -> {msisdn, decode_bcd(Addr, Buffer)};

decode_oa_da(<<3, _, Addr/binary>>, Buffer) -> {smsc, decode_bcd(Addr, Buffer)};

decode_oa_da(<<16#ff, _Addr/binary>>, _Buffer) -> {omit, undefined}.

decode_auth_tuple(<<?RAND_HEX, Len, Rand:Len/binary, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{rand => Rand});

decode_auth_tuple(<<?SRES_HEX, Len, SRES:Len/binary, Tail/binary>>, Map) when Len == 4 ->
  decode_auth_tuple(Tail, Map#{sres => SRES});

decode_auth_tuple(<<?KC_HEX, Len, KC:Len/binary, Tail/binary>>, Map) when Len == 8 ->
  decode_auth_tuple(Tail, Map#{kc => KC});

decode_auth_tuple(<<?IK_HEX, Len, IK:Len/binary, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{ik => IK});

decode_auth_tuple(<<?CK_HEX, Len, CK:Len/binary, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{ck => CK});

decode_auth_tuple(<<?AUTN_HEX, Len, AUTN:Len/binary, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{autn => AUTN});

decode_auth_tuple(<<?RES_HEX, Len, Res:Len/binary, Tail/binary>>, Map) ->
  decode_auth_tuple(Tail, Map#{res => Res});

decode_auth_tuple(<<>>, Map) -> Map.

decode_pdp_info(<<?PDP_CONTEXT_ID_HEX, Len, PDPContextId:Len/unit:8, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{pdp_context_id => PDPContextId});

decode_pdp_info(<<?PDP_TYPE_HEX, Len, PDPType:Len/unit:8, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{pdp_type => PDPType});

decode_pdp_info(<<?ACCESS_POINT_NAME_HEX, Len, APName:Len/binary, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{access_point_name => APName});

decode_pdp_info(<<?QUALITY_OF_SERVICE_HEX, Len, QOS:Len/binary, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{quality_of_service => QOS});

decode_pdp_info(<<?PDP_CHARGING_HEX, Len, PDPCharging:Len/unit:8, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{pdp_charging => PDPCharging});

decode_pdp_info(<<>>, Map) -> Map.

gsup_messages() ->
  #{
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
  }.

-spec encode('GSUPMessage'()) -> {ok, binary()} | {error, term()}.
encode(GSUPMessage = #{message_type := MsgAtom}) when is_atom(MsgAtom) ->
  Table = #{
    lu_request => 16#04, lu_error => 16#05, lu_result => 16#06,
    sai_request => 16#08, sai_error => 16#09, sai_result => 16#0a,
    purge_ms_request => 16#0c, purge_ms_error => 16#0d, purge_ms_result => 16#0e,
    af_report => 16#0b,
    isd_request => 16#10, isd_error => 16#11, isd_result => 16#12,
    dsd_request => 16#14, dsd_error => 16#15, dsd_result => 16#16,
    lc_request => 16#1c, lc_error => 16#1d, lc_result => 16#1e,
    ss_request => 16#20, ss_error => 16#21, ss_result => 16#22,
    mo_forward_request => 16#24, mo_forward_error => 16#25, mo_forward_result => 16#26,
    mt_forward_request => 16#28, mt_forward_error => 16#29, mt_forward_result => 16#2a,
    ready_for_sm_request => 16#2c, ready_for_sm_error => 16#2d, ready_for_sm_result => 16#2e,
    ci_request => 16#30, ci_error => 16#31, ci_result => 16#32
  },
  #{MsgAtom := MsgNum} = Table,
  encode(MsgNum, GSUPMessage).

encode(MsgNum, GSUPMessage) when is_integer(MsgNum), is_map(GSUPMessage), MsgNum >=0, MsgNum =< 255 ->
  case gsup_messages() of
    #{MsgNum := #{message_type := _Msg, mandatory := Mandatory, possible := Possible}} ->
      case {maps:size(maps:with(Mandatory, GSUPMessage)) == length(Mandatory), maps:size(maps:without(Possible ++ [message_type], GSUPMessage)) == 0} of
        {true, true} -> 
          Tail = encode_ie(GSUPMessage, <<>>),
          Len = size(Tail) + 2,
          {ok, <<Len:16, 16#ee, 16#05, MsgNum, Tail/binary>>};
        {false, _} -> {error, {ie_missing, Mandatory -- maps:keys(GSUPMessage)}};
        {_, false} -> {error, {ie_not_expected, maps:keys(GSUPMessage) -- Possible ++ [message_type]}}
      end;
    _ -> 
      {error, unknown_message}
  end.

encode_ie(#{imsi := Value0} = GSUPMessage, Tail) ->
  Value = encode_bcd(Value0, <<>>),
  Len = size(Value),
  encode_ie(maps:without([imsi], GSUPMessage), <<Tail/binary, ?IMSI_HEX, Len, Value/binary>>);

encode_ie(#{cause := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([cause], GSUPMessage), <<Tail/binary, ?CAUSE_HEX, Len, Value/binary>>);

encode_ie(#{auth_tuples := Tuples0} = GSUPMessage, Tail) ->
  Tuples = <<
    begin
      true = check_auth_tuple(Tuple),
      Value = encode_auth_tuple(Tuple, <<>>),
      Len = size(Value),
      <<?AUTH_TUPLE_HEX, Len, Value/binary>>
    end || Tuple <- Tuples0>>,
  encode_ie(maps:without([auth_tuples], GSUPMessage), <<Tail/binary, Tuples/binary>>);

encode_ie(#{pdp_info_complete := _} = GSUPMessage, Tail) ->
  encode_ie(maps:without([pdp_info_complete], GSUPMessage), <<Tail/binary, ?PDP_INFO_COMPLETE_HEX, 0>>);

encode_ie(#{pdp_info_list := PDPInfoList0} = GSUPMessage, Tail) -> %% PDPInfo
  PDPInfoList = <<
    begin
      true = check_pdp_info(PDPInfo),
      Value = encode_pdp_info(PDPInfo, <<>>),
      Len = size(Value),
      <<?PDP_INFO_HEX, Len, Value/binary>>
    end || PDPInfo <- PDPInfoList0>>,
  encode_ie(maps:without([pdp_info_list], GSUPMessage), <<Tail/binary, PDPInfoList/binary>>);

encode_ie(#{cancellation_type := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([cancellation_type], GSUPMessage), <<Tail/binary, ?CANCELLATION_TYPE_HEX, Len, Value/binary>>);

encode_ie(#{freeze_p_tmsi := Value} = GSUPMessage, Tail) ->
  Len = size(Value),
  encode_ie(maps:without([freeze_p_tmsi], GSUPMessage), <<Tail/binary, ?FREEZE_P_TMSI_HEX, Len, Value/binary>>);

encode_ie(#{msisdn := Value0} = GSUPMessage, Tail) ->
  Value = encode_bcd(Value0, <<>>),
  Len = size(Value) + 1,
  encode_ie(maps:without([msisdn], GSUPMessage), <<Tail/binary, ?MSISDN_HEX, Len, 16#06, Value/binary>>);

encode_ie(#{hlr_number := Value0} = GSUPMessage, Tail) ->
  Value = encode_bcd(Value0, <<>>),
  Len = size(Value) + 1,
  encode_ie(maps:without([hlr_number], GSUPMessage), <<Tail/binary, ?HLR_NUMBER_HEX, Len, 16#06, Value/binary>>);

encode_ie(#{pdp_context_id := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([pdp_context_id], GSUPMessage), <<Tail/binary, ?PDP_CONTEXT_ID_HEX, Len, Value/binary>>);

encode_ie(#{pdp_charging := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([pdp_charging], GSUPMessage), <<Tail/binary, ?PDP_CHARGING_HEX, Len, Value/binary>>);

encode_ie(#{rand := Value} = GSUPMessage, Tail) ->
  encode_ie(maps:without([rand], GSUPMessage), <<Tail/binary, ?RAND_HEX, 16, Value:16/unit:8>>);

encode_ie(#{auts := Value} = GSUPMessage, Tail) ->
  encode_ie(maps:without([auts], GSUPMessage), <<Tail/binary, ?AUTS_HEX, 14, Value:14/unit:8>>);

encode_ie(#{cn_domain := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([cn_domain], GSUPMessage), <<Tail/binary, ?CN_DOMAIN_HEX, Len, Value/binary>>);

encode_ie(#{session_id := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([session_id], GSUPMessage), <<Tail/binary, ?SESSION_ID_HEX, Len, Value/binary>>);

encode_ie(#{session_state := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([session_state], GSUPMessage), <<Tail/binary, ?SESSION_STATE_HEX, Len, Value/binary>>);

encode_ie(#{ss_info := Value} = GSUPMessage, Tail) ->
  Len = size(Value),
  encode_ie(maps:without([ss_info], GSUPMessage), <<Tail/binary, ?SS_INFO_HEX, Len, Value/binary>>);

encode_ie(#{sm_rp_mr := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([sm_rp_mr], GSUPMessage), <<Tail/binary, ?SM_RP_MR_HEX, Len, Value/binary>>);

encode_ie(#{sm_rp_da := Value0} = GSUPMessage, Tail) ->
  Value = encode_oa_da(Value0),
  Len = size(Value),
  encode_ie(maps:without([sm_rp_da], GSUPMessage), <<Tail/binary, ?SM_RP_DA_HEX, Len, Value/binary>>);

encode_ie(#{sm_rp_oa := Value0} = GSUPMessage, Tail) ->
  Value = encode_oa_da(Value0),
  Len = size(Value),
  encode_ie(maps:without([sm_rp_oa], GSUPMessage), <<Tail/binary, ?SM_RP_OA_HEX, Len, Value/binary>>);

encode_ie(#{sm_rp_ui := Value} = GSUPMessage, Tail) ->
  Len = size(Value),
  encode_ie(maps:without([sm_rp_ui], GSUPMessage), <<Tail/binary, ?SM_RP_UI_HEX, Len, Value/binary>>);

encode_ie(#{sm_rp_cause := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([sm_rp_cause], GSUPMessage), <<Tail/binary, ?SM_RP_CAUSE_HEX, Len, Value/binary>>);

encode_ie(#{sm_rp_mms := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([sm_rp_mms], GSUPMessage), <<Tail/binary, ?SM_RP_MMS_HEX, Len, Value/binary>>);

encode_ie(#{sm_alert_reason := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([sm_alert_reason], GSUPMessage), <<Tail/binary, ?SM_ALERT_REASON_HEX, Len, Value/binary>>);

encode_ie(#{imei := Value} = GSUPMessage, Tail) ->
  Len = size(Value),
  encode_ie(maps:without([imei], GSUPMessage), <<Tail/binary, ?IMEI_HEX, Len, Value/binary>>);

encode_ie(#{imei_check_result := Value0} = GSUPMessage, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_ie(maps:without([imei_check_result], GSUPMessage), <<Tail/binary, ?IMEI_CHECK_RESULT_HEX, Len, Value/binary>>);

encode_ie(_, Tail) -> Tail.

encode_bcd(<<A, B, Tail/binary>>, Buffer) when A =< $9, A >= $0, B =< $9, B >= $0 ->
  encode_bcd(Tail, <<Buffer/binary, B:4, A:4>>);

encode_bcd(<<A>>, Buffer) when A =< $9, A >= $0 ->
  <<Buffer/binary, 16#f:4, A:4>>;

encode_bcd(<<>>, Buffer) ->
  Buffer.

encode_oa_da({imsi, Addr}) -> <<16#01, (encode_bcd(Addr, <<>>))/binary>>;

encode_oa_da({msisdn, Addr}) -> <<16#02, 16#06, (encode_bcd(Addr, <<>>))/binary>>;

encode_oa_da({smsc, Addr}) -> <<16#03, 16#00, (encode_bcd(Addr, <<>>))/binary>>;

encode_oa_da({omit, _}) -> <<16#ff>>.

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ff -> <<X:8>>;

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ffff -> <<X:16>>;

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ffffff -> <<X:24>>;

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ffffffff -> <<X:32>>.

check_auth_tuple(AuthTuple) ->
  Mandatory = [rand, sres, kc],
  Possible = [rand, sres, kc, ik, ck, autn, res],
  (maps:size(maps:with(Mandatory, AuthTuple)) == length(Mandatory)) and (maps:size(maps:without(Possible, AuthTuple)) == 0).

check_pdp_info(PDPInfo) ->
  Mandatory = [],
  Possible = [pdp_context_id, pdp_type, access_point_name, quality_of_service, pdp_charging],
  (maps:size(maps:with(Mandatory, PDPInfo)) == length(Mandatory)) and (maps:size(maps:without(Possible, PDPInfo)) == 0).

encode_auth_tuple(#{rand := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([rand], Map), <<Buffer/binary, ?RAND_HEX, Len, Value:Len/binary>>);

encode_auth_tuple(#{sres := Value} = Map, Buffer) ->
  Len = 4,
  encode_auth_tuple(maps:without([sres], Map), <<Buffer/binary, ?SRES_HEX, Len, Value:Len/binary>>);

encode_auth_tuple(#{kc := Value} = Map, Buffer) ->
  Len = 8,
  encode_auth_tuple(maps:without([kc], Map), <<Buffer/binary, ?KC_HEX, Len, Value:Len/binary>>);

encode_auth_tuple(#{ik := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([ik], Map), <<Buffer/binary, ?IK_HEX, Len, Value:Len/binary>>);

encode_auth_tuple(#{ck := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([ck], Map), <<Buffer/binary, ?CK_HEX, Len, Value:Len/binary>>);

encode_auth_tuple(#{autn := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([autn], Map), <<Buffer/binary, ?AUTN_HEX, Len, Value:Len/binary>>);

encode_auth_tuple(#{res := Value} = Map, Buffer) ->
  Len = size(Value),
  encode_auth_tuple(maps:without([res], Map), <<Buffer/binary, ?RES_HEX, Len, Value/binary>>);

encode_auth_tuple(#{}, Buffer) -> Buffer.

encode_pdp_info(#{pdp_context_id := Value} = Map, Buffer) ->
  Len = 1,
  encode_pdp_info(maps:without([pdp_context_id], Map), <<Buffer/binary, ?PDP_CONTEXT_ID_HEX, Len, Value:Len/unit:8>>);

encode_pdp_info(#{pdp_type := Value} = Map, Buffer) ->
  Len = 2,
  encode_pdp_info(maps:without([pdp_type], Map), <<Buffer/binary, ?PDP_TYPE_HEX, Len, Value:Len/unit:8>>);

encode_pdp_info(#{access_point_name := Value} = Map, Buffer) ->
  Len = size(Value),
  encode_pdp_info(maps:without([access_point_name], Map), <<Buffer/binary, ?ACCESS_POINT_NAME_HEX, Len, Value/binary>>);

encode_pdp_info(#{quality_of_service := Value} = Map, Buffer) ->
  Len = size(Value),
  encode_pdp_info(maps:without([quality_of_service], Map), <<Buffer/binary, ?QUALITY_OF_SERVICE_HEX, Len, Value/binary>>);

encode_pdp_info(#{pdp_charging := Value} = Map, Buffer) ->
  Len = 2,
  encode_pdp_info(maps:without([pdp_charging], Map), <<Buffer/binary, ?PDP_CHARGING_HEX, Len, Value:Len/unit:8>>);

encode_pdp_info(#{}, Buffer) -> Buffer.

-ifdef (TEST).

-define(BINARY_ISD_REQUEST_BAD, <<0,33,238,5, 16,1,8,98,66,130,119,116,88,81,242,5,7,16,1,1,18,2,1,42,8,7,6,148,97,49,100,96,33,40,1,1>>).
-define(BINARY_ISD_REQUEST, <<0,35,238,5, 16,1,8,98,66,130,119,116,88,81,242,4,0,5,7,16,1,1,18,2,1,42,8,7,6,148,97,49,100,96,33,40,1,1>>).
-define(MAP_ISD_REQUEST, #{cn_domain => 1,imsi => <<"262428774785152">>,message_type => isd_request,msisdn => <<"491613460612">>,pdp_info_list => [#{access_point_name => <<1,42>>,pdp_context_id => 1}], pdp_info_complete => <<>>}).

-define(BINARY_MO_FORWARD_REQUEST, <<0,44,238,5, 36,1,8,98,66,2,0,0,0,128,248,64,1,66,65,5,3,0,137,103,245,66,8,2,6,148,33,3,0,0,136,67,10,5,35,5,0,33,67,245,0,0,0>>).
-define(MAP_MO_FORWARD_REQUEST, #{imsi => <<"262420000000088">>,message_type => mo_forward_request,sm_rp_da => {smsc,<<"98765">>},sm_rp_mr => 66,sm_rp_oa => {msisdn,<<"491230000088">>},sm_rp_ui => <<5,35,5,0,33,67,245,0,0,0>>}).

-define(BINARY_SS_REQUEST, <<0,44,238,5, 32,1,8,98,66,2,0,0,0,64,246,48,4,32,0,0,1,49,1,1,53,21,161,19,2,1,5,2,1,59,48,11,4,1,15,4,6,170,81,12,6,27,1>>).
-define(MAP_SS_REQUEST, #{imsi => <<"262420000000046">>,message_type => ss_request,session_id => 536870913,session_state => 1,ss_info => <<161,19,2,1,5,2,1,59,48,11,4,1,15,4,6,170,81,12,6,27,1>>}).

-define(BINARY_SAI_RESULT,<<0,192,238,5, 10,1,8,98,66,2,80,118,115,7,240,3,34,32,16,139,144,41,228,197,232,161,115,52,229,66,150,129,111,14,163,33,4,154,221,96,95,34,8,214,95,14,186,82,93,186,131,3,34,32,16,98,45,225,235,92,202,105,88,14,17,66,100,38,60,70,60,33,4,125,216,104,213,34,8,92,188,236,132,7,137,137,207,3,34,32,16,247,184,92,22,164,154,219,122,73,61,217,228,64,22,207,229,33,4,12,236,133,61,34,8,2,247,249,165,41,173,134,71,3,34,32,16,115,152,209,15,231,72,227,254,143,199,185,130,91,206,171,41,33,4,236,133,225,34,34,8,67,180,13,145,7,174,211,12,3,34,32,16,251,173,219,197,60,132,202,24,53,87,236,186,86,175,231,59,33,4,61,86,38,102,34,8,224,104,249,198,53,145,182,54>>).
-define(MAP_SAI_RESULT, #{auth_tuples => [
    #{kc => <<15447081440312670851:8/unit:8>>,rand => <<185511231865796904634040334886313594531:16/unit:8>>,sres => <<2598199391:4/unit:8>>},
    #{kc => <<6682475998917265871:8/unit:8>>,rand => <<130502579135052156657755432460855559740:16/unit:8>>,sres => <<2111334613:4/unit:8>>},
    #{kc => <<213913995087545927:8/unit:8>>,rand => <<329276565356490492799345768940241866725:16/unit:8>>,sres => <<216827197:4/unit:8>>},
    #{kc => <<4878539212899406604:8/unit:8>>,rand => <<153654688921371376697326139997978274601:16/unit:8>>,sres => <<3968196898:4/unit:8>>},
    #{kc => <<16170449091771348534:8/unit:8>>,rand => <<334538951772921257466553732075468351291:16/unit:8>>,sres => <<1029056102:4/unit:8>>}
  ],imsi => <<"262420056737700">>,message_type => sai_result}).

isd_request_test() ->
  {ok, {Map, <<>>}} = gsup_protocol:decode(?BINARY_ISD_REQUEST),
  ?assertEqual(?MAP_ISD_REQUEST, Map),
  {ok, Bin} = gsup_protocol:encode(Map),
  ?assertEqual(?BINARY_ISD_REQUEST, Bin).

mo_forward_request_test() ->
  {ok, {Map, <<>>}} = gsup_protocol:decode(?BINARY_MO_FORWARD_REQUEST),
  ?assertEqual(?MAP_MO_FORWARD_REQUEST, Map),
  {ok, Bin} = gsup_protocol:encode(Map),
  ?assertEqual(?BINARY_MO_FORWARD_REQUEST, Bin).

ss_request_test() ->
  {ok, {Map, <<>>}} = gsup_protocol:decode(?BINARY_SS_REQUEST),
  ?assertEqual(?MAP_SS_REQUEST, Map),
  {ok, Bin} = gsup_protocol:encode(Map),
  ?assertEqual(?BINARY_SS_REQUEST, Bin).

sai_result_test() ->
  {ok, {Map, <<>>}} = gsup_protocol:decode(?BINARY_SAI_RESULT),
  ?assertEqual(?MAP_SAI_RESULT, Map),
  {ok, Bin} = gsup_protocol:encode(Map),
  ?assertEqual(?BINARY_SAI_RESULT, Bin).

missing_params_test() ->
  Res1 = gsup_protocol:decode(?BINARY_ISD_REQUEST_BAD),
  ?assertEqual({error,{ie_missing,[pdp_info_complete]}}, Res1),
  Res2 = gsup_protocol:encode(#{message_type => mo_forward_request, imsi => <<"123456">>}),
  ?assertEqual({error,{ie_missing,[sm_rp_mr,sm_rp_da,sm_rp_oa,sm_rp_ui]}}, Res2).

excess_params_test() ->
  Res1 = gsup_protocol:encode(#{message_type => lu_error,imsi => <<"1234">>,cause => 1,pdp_info_complete => <<>>}),
  ?assertEqual({error,{ie_not_expected,[pdp_info_complete]}}, Res1).

-endif.
