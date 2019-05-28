-module(gsup_protocol).

-include ("gsup_protocol.hrl").

-export([decode/1, encode/1, decode_bcd/1]).
-export_type(['GSUPMessage'/0, 'GSUPMessageType'/0]).

-spec decode(binary()) -> {ok, {'GSUPMessage'(), binary()}} | {more_data, binary()} | {error, term()}.
decode(<<PSize:16, ?OSMO_EXT, Packet:PSize/binary, Rest/binary>>) ->
  <<?GSUP_OSMO_EXT, MsgNum, Tail/binary>> = Packet,
  GSUPMessage = decode_ie(Tail, #{}),
  case ?GSUP_MESSAGES() of
    #{MsgNum := #{message_type := Msg, mandatory := Mandatory, possible := Possible}} ->
      case {maps:size(maps:with(Mandatory, GSUPMessage)) == length(Mandatory), maps:size(maps:without(Possible ++ [message_type], GSUPMessage)) == 0} of
        {true, true} -> {ok, {GSUPMessage#{message_type => Msg}, Rest}};
        {false, _} -> {error, {ie_missing, Mandatory -- maps:keys(GSUPMessage)}};
        {_, false} -> {error, {ie_not_expected, maps:keys(GSUPMessage) -- Possible}}
      end;
    _ -> 
      {error, {unknown_message, MsgNum, GSUPMessage}}
  end;

decode(<<_PSize:16, X, _/binary>> = Rest) when X /= ?OSMO_EXT ->
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

-spec encode('GSUPMessage'()) -> {ok, binary()} | {error, term()}.
encode(GSUPMessage = #{message_type := MsgAtom}) when is_atom(MsgAtom) ->
  F = fun
    (MsgNum_, #{message_type := MsgAtom_}, undefined) when MsgAtom_ == MsgAtom -> MsgNum_;
    (_, _, Acc) -> Acc
  end,
  case maps:fold(F, undefined, ?GSUP_MESSAGES()) of
    undefined -> error({unknown_message, MsgAtom}), MsgNum = undefined;
    MsgNum when is_integer(MsgNum) -> ok
  end,
  encode(MsgNum, GSUPMessage).

encode(MsgNum, GSUPMessage) when is_integer(MsgNum), is_map(GSUPMessage), MsgNum >=0, MsgNum =< 255 ->
  case ?GSUP_MESSAGES() of
    #{MsgNum := #{message_type := _Msg, mandatory := Mandatory, possible := Possible}} ->
      case {maps:size(maps:with(Mandatory, GSUPMessage)) == length(Mandatory), maps:size(maps:without(Possible ++ [message_type], GSUPMessage)) == 0} of
        {true, true} -> 
          Tail = encode_ie(GSUPMessage, <<>>),
          Len = size(Tail) + 2,
          {ok, <<Len:16, ?OSMO_EXT, ?GSUP_OSMO_EXT, MsgNum, Tail/binary>>};
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
