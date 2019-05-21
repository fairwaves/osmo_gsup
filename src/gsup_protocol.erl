-module(gsup_protocol).

-export ([decode/1, encode/1]).

decode(<<PSize:16, 16#ee, Packet:PSize/binary, Rest/binary>>) ->
  <<16#05, MsgNum, Tail/binary>> = Packet,
  Messages = known_messages(),
  Params = decode_iei(Tail, #{}),
  case Messages of
    #{MsgNum := #{msg := Msg, mandatory := Mandatory, fields := Fields}} ->
      case {maps:size(maps:with(Mandatory, Params)) == length(Mandatory), maps:size(maps:without(Fields, Params)) == 0} of
        {true, true} -> {ok, {Params#{message_type => Msg}, Rest}};
        {false, _} -> {error, {params_missing, Mandatory -- maps:keys(Params)}};
        {_, false} -> {error, {params_not_expected, maps:keys(Params) -- Fields}}
      end;
    _ -> 
      {error, {unknown_message, MsgNum, Params}}
  end;

decode(<<_PSize:16, X, _/binary>> = Rest) when X /= 16#ee ->
  {error, {bad_packet, Rest}};

decode(Rest) ->
  {more_data, Rest}.

decode_iei(<<>>, Map) -> Map;

decode_iei(<<16#01, Len, IMSI:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{imsi => decode_imsi(IMSI, <<>>)});

decode_iei(<<16#02, Len, Cause:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{cause => Cause});

decode_iei(<<16#03, Len, AuthTuple0:Len/binary, Tail/binary>>, Map) ->
  List = maps:get(auth_tuples, Map, []),
  AuthTuple = decode_auth_tuple(AuthTuple0, #{}),
  true = check_auth_tuple(AuthTuple),
  decode_iei(Tail, Map#{auth_tuples => List ++ [AuthTuple]});

decode_iei(<<16#04, 0, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{pdp_info_complete => <<>>});

decode_iei(<<16#05, Len, PDPInfo0:Len/binary, Tail/binary>>, Map) ->
  List = maps:get(pdp_info, Map, []),
  PDPInfo = decode_pdp_info(PDPInfo0, #{}),
  true = check_pdp_info(PDPInfo),
  decode_iei(Tail, Map#{pdp_info => List ++ [PDPInfo]});

decode_iei(<<16#06, Len, CancellationType:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{cancellation_type => CancellationType});

decode_iei(<<16#07, Len, FreezePTMSI:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{freeze_p_tmsi => FreezePTMSI});

decode_iei(<<16#08, Len, MSISDN:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{msisdn => decode_msisdn(MSISDN, <<>>)});

decode_iei(<<16#09, Len, HLRNumber:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{hlr_number => decode_msisdn(HLRNumber, <<>>)});

decode_iei(<<16#10, Len, PDPContextId:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{pdp_context_id => PDPContextId});

decode_iei(<<16#14, Len, PDPCharging:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{pdp_charging => PDPCharging});

decode_iei(<<16#20, Len, Rand:Len/unit:8, Tail/binary>>, Map) when Len == 16->
  decode_iei(Tail, Map#{rand => Rand});

decode_iei(<<16#26, Len, AUTS:Len/unit:8, Tail/binary>>, Map) when Len == 14 ->
  decode_iei(Tail, Map#{auts => AUTS});

decode_iei(<<16#28, Len, CNDomain:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{cndomain => CNDomain});

decode_iei(<<16#30, Len, SesID:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{session_id => SesID});

decode_iei(<<16#31, Len, SesState:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{session_state => SesState});

decode_iei(<<16#35, Len, SesInfo:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{ss_info => SesInfo});

decode_iei(<<16#40, Len, MsgRef:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_rp_mr => MsgRef});

decode_iei(<<16#41, Len, DA:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_rp_da => decode_oa_da(DA, <<>>)});

decode_iei(<<16#42, Len, OA:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_rp_oa => decode_oa_da(OA, <<>>)});

decode_iei(<<16#43, Len, MessageBody:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_rp_ui => MessageBody});

decode_iei(<<16#44, Len, RPCause:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_rp_cause => RPCause});

decode_iei(<<16#45, Len, RPMMS:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_rp_mms => RPMMS});

decode_iei(<<16#46, Len, AlertReason:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{sm_alert_reason => AlertReason});

decode_iei(<<16#50, Len, IMEI:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{imei => IMEI});

decode_iei(<<16#51, Len, IMEIResult:Len/unit:8, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{imei_check_result => IMEIResult}).

decode_imsi(<<>>, Buffer) -> Buffer;

decode_imsi(<<A:4, B:4, Tail/binary>>, Buffer) when A < 10, B < 10 ->
  decode_imsi(Tail, <<Buffer/binary, ($0 + B), ($0 + A)>>);

decode_imsi(<<_:4, B:4, _Tail/binary>>, Buffer) when B < 10 ->
  <<Buffer/binary, ($0 + B)>>.

decode_msisdn(<<_X, Data/binary>>, Buffer) -> decode_imsi(Data, Buffer).


decode_oa_da(<<1, Addr/binary>>, Buffer) -> {imsi, decode_imsi(Addr, Buffer)};

decode_oa_da(<<2, Addr/binary>>, Buffer) -> {msisdn, decode_imsi(Addr, Buffer)};

decode_oa_da(<<3, Addr/binary>>, Buffer) -> {smsc, decode_imsi(Addr, Buffer)};

decode_oa_da(<<16#ff, _Addr/binary>>, _Buffer) -> {omit, undefined}.

decode_auth_tuple(<<16#20, Len, Rand:Len/unit:8, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{rand => Rand});

decode_auth_tuple(<<16#21, Len, SRES:Len/unit:8, Tail/binary>>, Map) when Len == 4 ->
  decode_auth_tuple(Tail, Map#{sres => SRES});

decode_auth_tuple(<<16#22, Len, KC:Len/unit:8, Tail/binary>>, Map) when Len == 8 ->
  decode_auth_tuple(Tail, Map#{kc => KC});

decode_auth_tuple(<<16#23, Len, IK:Len/unit:8, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{ik => IK});

decode_auth_tuple(<<16#24, Len, CK:Len/unit:8, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{ck => CK});

decode_auth_tuple(<<16#25, Len, AUTN:Len/unit:8, Tail/binary>>, Map) when Len == 16 ->
  decode_auth_tuple(Tail, Map#{autn => AUTN});

decode_auth_tuple(<<16#27, Len, Res:Len/binary, Tail/binary>>, Map) ->
  decode_auth_tuple(Tail, Map#{res => Res});

decode_auth_tuple(<<>>, Map) -> Map.

decode_pdp_info(<<16#10, Len, PDPContextId:Len/unit:8, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{pdp_context_id => PDPContextId});

decode_pdp_info(<<16#11, Len, PDPType:Len/unit:8, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{pdp_type => PDPType});

decode_pdp_info(<<16#12, Len, APName:Len/binary, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{access_point_name => APName});

decode_pdp_info(<<16#13, Len, QOS:Len/binary, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{quality_of_service => QOS});

decode_pdp_info(<<16#14, Len, PDPCharging:Len/unit:8, Tail/binary>>, Map) ->
  decode_pdp_info(Tail, Map#{pdp_charging => PDPCharging});

decode_pdp_info(<<>>, Map) -> Map.

known_messages() ->
  #{
    16#04 => #{msg => lu_request, mandatory => [imsi], fields => [imsi, cndomain]},
    16#05 => #{msg => lu_error, mandatory => [imsi, cause], fields => [imsi, cause]},
    16#06 => #{msg => lu_result, mandatory => [imsi], fields => [imsi, msisdn, hlr_number, pdp_info_complete, pdp_info]},
    16#08 => #{message_type => sai_request, mandatory => [imsi], fields => [imsi, cndomain, auts, rand]},
    16#09 => #{message_type => sai_error, mandatory => [imsi, cause], fields => [imsi, cause]},
    16#0a => #{message_type => sai_result, mandatory => [imsi], fields => [imsi, auth_tuples]},
    16#0b => #{message_type => af_report, mandatory => [imsi], fields => [imsi, cndomain]},
    16#0c => #{message_type => purge_ms_request, mandatory => [imsi, hlr_number], fields => [imsi, cndomain, hlr_number]},
    16#0d => #{message_type => purge_ms_error, mandatory => [imsi, cause], fields => [imsi, cause]},
    16#0e => #{message_type => purge_ms_result, mandatory => [imsi, freeze_p_tmsi], fields => [imsi, freeze_p_tmsi]},
    16#10 => #{msg => isd_request, mandatory => [imsi, pdp_info_complete], fields => [imsi, cndomain, msisdn, hlr_number, pdp_info_complete, pdp_info, pdp_charging]},
    16#11 => #{msg => isd_error, mandatory => [imsi, cause], fields => [imsi, cause]},
    16#12 => #{msg => isd_result, mandatory => [imsi], fields => [imsi]},
    16#14 => #{message_type => dsd_request, mandatory => [imsi], fields => [imsi, cndomain, pdp_context_id]},
    16#15 => #{message_type => dsd_error, mandatory => [imsi, cause], fields => [imsi, cause]},
    16#16 => #{message_type => dsd_result, mandatory => [imsi], fields => [imsi]},
    16#1c => #{message_type => lc_request, mandatory => [imsi], fields => [imsi, cndomain, cancellation_type]},
    16#1d => #{message_type => lc_error, mandatory => [imsi, cause], fields => [imsi, cndomain]},
    16#1e => #{message_type => lc_result, mandatory => [imsi], fields => [imsi, cndomain]},
    16#20 => #{msg => ss_request, mandatory => [session_id, session_state, imsi], fields => [imsi, session_id, session_state, ss_info]},
    16#21 => #{msg => ss_error, mandatory => [session_id, session_state, imsi, cause], fields => [imsi, cause, session_id, session_state]},
    16#22 => #{msg => ss_result, mandatory => [session_id, session_state, imsi], fields => [imsi, session_id, session_state, ss_info]},
    16#24 => #{msg => mo_forward_request, mandatory => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui], fields => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui]},
    16#25 => #{msg => mo_forward_error, mandatory => [sm_rp_mr, imsi, sm_rp_cause], fields => [sm_rp_mr, imsi, sm_rp_cause, sm_rp_ui]},
    16#26 => #{msg => mo_forward_result, mandatory => [sm_rp_mr, imsi], fields => [sm_rp_mr, imsi]},
    16#28 => #{msg => mt_forward_request, mandatory => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui], fields => [sm_rp_mr, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui, sm_rp_mms]},
    16#29 => #{msg => mt_forward_error, mandatory => [sm_rp_mr, imsi, sm_rp_cause], fields => [sm_rp_mr, imsi, sm_rp_cause, sm_rp_ui]},
    16#2a => #{msg => mt_forward_result, mandatory => [sm_rp_mr, imsi], fields => [sm_rp_mr, imsi]},
    16#2c => #{message_type => ready_for_sm_request, mandatory => [imsi, sm_rp_mr, sm_alert_reason], fields => [imsi, sm_rp_mr, sm_alert_reason]},
    16#2d => #{message_type => ready_for_sm_error, mandatory => [imsi, sm_rp_mr, sm_sm_rp_cause], fields => [imsi, sm_rp_mr, sm_sm_rp_cause, sm_rp_ui]},
    16#2e => #{message_type => ready_for_sm_result, mandatory => [imsi, sm_rp_mr], fields => [imsi, sm_rp_mr]},
    16#30 => #{message_type => ci_request, mandatory => [imsi, imei], fields => [imsi, imei]},
    16#31 => #{message_type => ci_error, mandatory => [imsi, cause], fields => [imsi, cause]},
    16#32 => #{message_type => ci_result, mandatory => [imsi, imei_check_result], fields => [imsi, imei_check_result]}
  }.

encode(Params = #{message_type := MsgAtom}) when is_atom(MsgAtom) ->
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
  encode(MsgNum, Params).

encode(MsgNum, Params) when is_integer(MsgNum), is_map(Params), MsgNum >=0, MsgNum =< 255 ->
  case known_messages() of
    #{MsgNum := #{msg := _Msg, mandatory := Mandatory, fields := Fields}} ->
      case {maps:size(maps:with(Mandatory, Params)) == length(Mandatory), maps:size(maps:without(Fields, Params)) == 0} of
        {true, true} -> 
          Tail = encode_iei(Params, <<>>),
          Len = size(Tail) + 2,
          {ok, <<Len:16, 16#ee, 16#05, MsgNum, Tail/binary>>};
        {false, _} -> {error, {params_missing, Mandatory -- maps:keys(Params)}};
        {_, false} -> {error, {params_not_expected, maps:keys(Params) -- Fields}}
      end;
    _ -> 
      {error, unknown_message}
  end.

encode_iei(#{imsi := Value0} = Params, Tail) ->
  Value = encode_imsi(Value0, <<>>),
  Len = size(Value),
  encode_iei(maps:without([imsi], Params), <<Tail/binary, (code_param(imsi)):8, Len, Value/binary>>);

encode_iei(#{cause := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([cause], Params), <<Tail/binary, (code_param(cause)):8, Len, Value/binary>>);

encode_iei(#{auth_tuples := []} = Params, Tail) ->
  encode_iei(maps:without([auth_tuples], Params), Tail);

encode_iei(#{auth_tuples := [Tuple | Tuples]} = Params, Tail) ->
  true = check_auth_tuple(Tuple),
  Value = encode_auth_tuple(Tuple, <<>>),
  Len = size(Value),
  encode_iei(Params#{auth_tuples => Tuples}, <<Tail/binary, (code_param(auth_tuples)):8, Len, Value/binary>>);

encode_iei(#{pdp_info_complete := _} = Params, Tail) ->
  encode_iei(maps:without([pdp_info_complete], Params), <<Tail/binary, (code_param(pdp_info_complete)):8, 0>>);

encode_iei(#{pdp_info := []} = Params, Tail) ->
  encode_iei(maps:without([pdp_info], Params), Tail);

encode_iei(#{pdp_info := [PDPInfo | PDPInfoList]} = Params, Tail) -> %% PDPInfo
  true = check_pdp_info(PDPInfo),
  Value = encode_pdp_info(PDPInfo, <<>>),
  Len = size(Value),
  encode_iei(Params#{pdp_info => PDPInfoList}, <<Tail/binary, (code_param(pdp_info)):8, Len, Value/binary>>);

encode_iei(#{cancellation_type := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([cancellation_type], Params), <<Tail/binary, (code_param(cancellation_type)):8, Len, Value/binary>>);

encode_iei(#{freeze_p_tmsi := Value} = Params, Tail) ->
  Len = size(Value),
  encode_iei(maps:without([freeze_p_tmsi], Params), <<Tail/binary, (code_param(freeze_p_tmsi)):8, Len, Value/binary>>);

encode_iei(#{msisdn := Value0} = Params, Tail) ->
  Value = encode_imsi(Value0, <<>>),
  Len = size(Value) + 1,
  encode_iei(maps:without([msisdn], Params), <<Tail/binary, (code_param(msisdn)):8, Len, 16#06, Value/binary>>);

encode_iei(#{hlr_number := Value0} = Params, Tail) ->
  Value = encode_imsi(Value0, <<>>),
  Len = size(Value) + 1,
  encode_iei(maps:without([hlr_number], Params), <<Tail/binary, (code_param(hlr_number)):8, Len, 16#06, Value/binary>>);

encode_iei(#{pdp_context_id := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([pdp_context_id], Params), <<Tail/binary, (code_param(pdp_context_id)):8, Len, Value/binary>>);

encode_iei(#{pdp_charging := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([pdp_charging], Params), <<Tail/binary, (code_param(pdp_charging)):8, Len, Value/binary>>);

encode_iei(#{rand := Value} = Params, Tail) ->
  encode_iei(maps:without([rand], Params), <<Tail/binary, (code_param(rand)):8, 16, Value:16/unit:8>>);

encode_iei(#{auts := Value} = Params, Tail) ->
  encode_iei(maps:without([auts], Params), <<Tail/binary, (code_param(auts)):8, 14, Value:14/unit:8>>);

encode_iei(#{cndomain := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([cndomain], Params), <<Tail/binary, (code_param(cndomain)):8, Len, Value/binary>>);

encode_iei(#{session_id := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([session_id], Params), <<Tail/binary, (code_param(session_id)):8, Len, Value/binary>>);

encode_iei(#{session_state := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([session_state], Params), <<Tail/binary, (code_param(session_state)):8, Len, Value/binary>>);

encode_iei(#{ss_info := Value} = Params, Tail) ->
  Len = size(Value),
  encode_iei(maps:without([ss_info], Params), <<Tail/binary, (code_param(ss_info)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_mr := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_mr], Params), <<Tail/binary, (code_param(sm_rp_mr)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_da := Value0} = Params, Tail) ->
  Value = encode_oa_da(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_da], Params), <<Tail/binary, (code_param(sm_rp_da)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_oa := Value0} = Params, Tail) ->
  Value = encode_oa_da(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_oa], Params), <<Tail/binary, (code_param(sm_rp_oa)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_ui := Value} = Params, Tail) ->
  Len = size(Value),
  encode_iei(maps:without([sm_rp_ui], Params), <<Tail/binary, (code_param(sm_rp_ui)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_cause := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_cause], Params), <<Tail/binary, (code_param(sm_rp_cause)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_mms := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_mms], Params), <<Tail/binary, (code_param(sm_rp_mms)):8, Len, Value/binary>>);

encode_iei(#{alert_reason := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([alert_reason], Params), <<Tail/binary, (code_param(alert_reason)):8, Len, Value/binary>>);

encode_iei(#{imei := Value} = Params, Tail) ->
  Len = size(Value),
  encode_iei(maps:without([imei], Params), <<Tail/binary, (code_param(imei)):8, Len, Value/binary>>);

encode_iei(#{imei_check_result := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([imei_check_result], Params), <<Tail/binary, (code_param(imei_check_result)):8, Len, Value/binary>>);

encode_iei(_, Tail) -> Tail.

encode_imsi(<<A, B, Tail/binary>>, Buffer) when A =< $9, A >= $0, B =< $9, B >= $0 ->
  encode_imsi(Tail, <<Buffer/binary, B:4, A:4>>);

encode_imsi(<<A>>, Buffer) when A =< $9, A >= $0 ->
  <<Buffer/binary, 16#f:4, A:4>>.

encode_oa_da({imsi, Addr}) -> <<16#01, (encode_imsi(Addr, <<>>))/binary>>;

encode_oa_da({msisdn, Addr}) -> <<16#02, 16#06, (encode_imsi(Addr, <<>>))/binary>>;

encode_oa_da({smsc, Addr}) -> <<16#03, 16#06, (encode_imsi(Addr, <<>>))/binary>>;

encode_oa_da({omit, _}) -> <<16#ff>>.

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ff -> <<X:8>>;

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ffff -> <<X:16>>;

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ffffff -> <<X:24>>;

encode_varint(X) when is_integer(X), X >= 0, X =< 16#ffffffff -> <<X:32>>.

check_auth_tuple(AuthTuple) ->
  Mandatory = [rand, sres, kc],
  Fields = [rand, sres, kc, ik, ck, autn, res],
  (maps:size(maps:with(Mandatory, AuthTuple)) == length(Mandatory)) and (maps:size(maps:without(Fields, AuthTuple)) == 0).

check_pdp_info(AuthTuple) ->
  Mandatory = [],
  Fields = [pdp_context_id, pdp_type, access_point_name, quality_of_service, pdp_charging],
  (maps:size(maps:with(Mandatory, AuthTuple)) == length(Mandatory)) and (maps:size(maps:without(Fields, AuthTuple)) == 0).

encode_auth_tuple(#{rand := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([rand], Map), <<Buffer/binary, (code_param(rand)):8, Len, Value:Len/unit:8>>);

encode_auth_tuple(#{sres := Value} = Map, Buffer) ->
  Len = 4,
  encode_auth_tuple(maps:without([sres], Map), <<Buffer/binary, (code_param(sres)):8, Len, Value:Len/unit:8>>);

encode_auth_tuple(#{kc := Value} = Map, Buffer) ->
  Len = 8,
  encode_auth_tuple(maps:without([kc], Map), <<Buffer/binary, (code_param(kc)):8, Len, Value:Len/unit:8>>);

encode_auth_tuple(#{ik := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([ik], Map), <<Buffer/binary, (code_param(ik)):8, Len, Value:Len/unit:8>>);

encode_auth_tuple(#{ck := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([ck], Map), <<Buffer/binary, (code_param(ck)):8, Len, Value:Len/unit:8>>);

encode_auth_tuple(#{autn := Value} = Map, Buffer) ->
  Len = 16,
  encode_auth_tuple(maps:without([autn], Map), <<Buffer/binary, (code_param(autn)):8, Len, Value:Len/unit:8>>);

encode_auth_tuple(#{res := Value} = Map, Buffer) ->
  Len = size(Value),
  encode_auth_tuple(maps:without([res], Map), <<Buffer/binary, (code_param(res)):8, Len, Value/binary>>);

encode_auth_tuple(#{}, Buffer) -> Buffer.

encode_pdp_info(#{pdp_context_id := Value} = Map, Buffer) ->
  Len = 1,
  encode_pdp_info(maps:without([pdp_context_id], Map), <<Buffer/binary, (code_param(pdp_context_id)):8, Len, Value:Len/unit:8>>);

encode_pdp_info(#{pdp_type := Value} = Map, Buffer) ->
  Len = 2,
  encode_pdp_info(maps:without([pdp_type], Map), <<Buffer/binary, (code_param(pdp_type)):8, Len, Value:Len/unit:8>>);

encode_pdp_info(#{access_point_name := Value} = Map, Buffer) ->
  Len = size(Value),
  encode_pdp_info(maps:without([access_point_name], Map), <<Buffer/binary, (code_param(access_point_name)):8, Len, Value/binary>>);

encode_pdp_info(#{quality_of_service := Value} = Map, Buffer) ->
  Len = size(Value),
  encode_pdp_info(maps:without([quality_of_service], Map), <<Buffer/binary, (code_param(quality_of_service)):8, Len, Value/binary>>);

encode_pdp_info(#{pdp_charging := Value} = Map, Buffer) ->
  Len = 2,
  encode_pdp_info(maps:without([pdp_charging], Map), <<Buffer/binary, (code_param(pdp_charging)):8, Len, Value:Len/unit:8>>);

encode_pdp_info(#{}, Buffer) -> Buffer.

code_param(imsi) -> 16#01;
code_param(cause) -> 16#02;
code_param(auth_tuples) -> 16#03;
code_param(pdp_info_complete) -> 16#04;
code_param(pdp_info) -> 16#05;
code_param(cancellation_type) -> 16#06;
code_param(freeze_p_tmsi) -> 16#07;
code_param(msisdn) -> 16#08;
code_param(hlr_number) -> 16#09;
code_param(pdp_context_id) -> 16#10;
code_param(pdp_type) -> 16#11;
code_param(access_point_name) -> 16#12;
code_param(quality_of_service) -> 16#13;
code_param(pdp_charging) -> 16#14;
code_param(rand) -> 16#20;
code_param(sres) -> 16#21;
code_param(kc) -> 16#22;
code_param(ik) -> 16#23;
code_param(ck) -> 16#24;
code_param(autn) -> 16#25;
code_param(auts) -> 16#26;
code_param(res) -> 16#27;
code_param(cndomain) -> 16#28;
code_param(session_id) -> 16#30;
code_param(session_state) -> 16#31;
code_param(ss_info) -> 16#35;
code_param(sm_rp_mr) -> 16#40;
code_param(sm_rp_da) -> 16#41;
code_param(sm_rp_oa) -> 16#42;
code_param(sm_rp_ui) -> 16#43;
code_param(sm_rp_cause) -> 16#44;
code_param(sm_rp_mms) -> 16#45;
code_param(alert_reason) -> 16#46;
code_param(imei) -> 16#50;
code_param(imei_check_result) -> 16#51.
