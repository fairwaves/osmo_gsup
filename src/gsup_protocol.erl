-module(gsup_protocol).

-export ([decode/1, encode/1]).

decode(<<PSize:16, 16#ee, Packet:PSize/binary, Rest/binary>>) ->
  <<16#05, MsgNum, Tail/binary>> = Packet,
  Messages = known_messages(),
  Params = decode_iei(Tail, #{}),
  case Messages of
    #{MsgNum := #{msg := Msg, mandatory := Mandatory}} ->
      case maps:size(maps:with(Mandatory, Params)) == length(Mandatory) of
        true -> {ok, {Params#{message_type => Msg}, Rest}};
        false -> {error, {params_missing, Mandatory, Params}}
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

decode_iei(<<16#03, Len, AuthTuple:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, decode_auth_tuple(AuthTuple, Map));

decode_iei(<<16#04, 0, Tail/binary>>, Map) ->
  decode_iei(Tail, Map#{pdp_info_complete => <<>>});

decode_iei(<<16#05, Len, PDPInfo:Len/binary, Tail/binary>>, Map) ->
  decode_iei(Tail, decode_pdp_info(PDPInfo, Map));

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
  decode_iei(Tail, Map#{imei_check_result => IMEIResult});

decode_iei(Tail, Map) -> 
  lager:info("Unknown tail: ~p", [Tail]),
  Map.

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
    16#04 => #{msg => lu_request, mandatory => [imsi]},
    16#05 => #{msg => lu_error, mandatory => [imsi, cause]},
    16#06 => #{msg => lu_result, mandatory => [imsi]},
    16#08 => #{message_type => sai_request, mandatory => [imsi]},
    16#09 => #{message_type => sai_error, mandatory => [imsi, cause]},
    16#0a => #{message_type => sai_result, mandatory => [imsi]},
    16#0b => #{message_type => af_report, mandatory => [imsi]},
    16#0c => #{message_type => purge_ms_request, mandatory => [imsi, hlr_number]},
    16#0d => #{message_type => purge_ms_error, mandatory => [imsi, cause]},
    16#0e => #{message_type => purge_ms_result, mandatory => [imsi]},
    16#10 => #{msg => isd_request, mandatory => [imsi]},
    16#11 => #{msg => isd_error, mandatory => [imsi, cause]},
    16#12 => #{msg => isd_result, mandatory => [imsi]},
    16#14 => #{message_type => dsd_request, mandatory => [imsi]},
    16#15 => #{message_type => dsd_error, mandatory => [imsi, cause]},
    16#16 => #{message_type => dsd_result, mandatory => [imsi]},
    16#1c => #{message_type => lc_request, mandatory => [imsi]},
    16#1d => #{message_type => lc_error, mandatory => [imsi, cause]},
    16#1e => #{message_type => lc_result, mandatory => [imsi]},
    16#20 => #{msg => ss_request, mandatory => [session_id, session_state, imsi]},
    16#21 => #{msg => ss_error, mandatory => [session_id, session_state, imsi, cause]},
    16#22 => #{msg => ss_result, mandatory => [session_id, session_state, imsi]},
    16#24 => #{msg => mo_forward_request, mandatory => [msg_ref, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui]},
    16#25 => #{msg => mo_forward_error, mandatory => [msg_ref, imsi, sm_rp_cause]},
    16#26 => #{msg => mo_forward_result, mandatory => [msg_ref, imsi]},
    16#28 => #{msg => mt_forward_request, mandatory => [msg_ref, imsi, sm_rp_da, sm_rp_oa, sm_rp_ui]},
    16#29 => #{msg => mt_forward_error, mandatory => [msg_ref, imsi, sm_rp_cause]},
    16#2a => #{msg => mt_forward_result, mandatory => [msg_ref, imsi]},
    16#2c => #{message_type => ready_for_sm_request, mandatory => [imsi, sm_rp_mr, sm_alert_reason]},
    16#2d => #{message_type => ready_for_sm_error, mandatory => [imsi, sm_rp_mr, sm_sm_rp_cause]},
    16#2e => #{message_type => ready_for_sm_result, mandatory => [imsi, sm_rp_mr]},
    16#30 => #{message_type => ci_request, mandatory => [imsi, imei]},
    16#31 => #{message_type => ci_error, mandatory => [imsi, cause]},
    16#32 => #{message_type => ci_result, mandatory => [imsi, imei_check_result]}
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
    #{MsgNum := #{msg := _Msg, text := Text, mandatory := Mandatory}} ->
      lager:info("Reply ~s: ~p", [Text, Params]),
      case maps:size(maps:with(Mandatory, Params)) == length(Mandatory) of
        true -> 
          Tail = encode_iei(Params, <<>>),
          Len = size(Tail) + 2,
          {ok, <<Len:16, 16#ee, 16#05, MsgNum, Tail/binary>>};
        false ->
          lager:warning("Mandatory params missing from ~p", [Mandatory]),
          {error, missing_params}
      end;
    _ -> 
      lager:info("Unknown message in reply (~p): ~p", [MsgNum, Params]),
      {error, unknown_message}
  end.

encode_iei(#{imsi := IMSI0} = Params, Tail) ->
  IMSI = encode_imsi(IMSI0, <<>>),
  Len = size(IMSI),
  encode_iei(maps:without([imsi], Params), <<Tail/binary, 16#01, Len, IMSI/binary>>);

encode_iei(#{session_info := Value} = Params, Tail) ->
  Len = size(Value),
  encode_iei(maps:without([session_info], Params), <<Tail/binary, (code_param(session_info)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_ui := Value} = Params, Tail) ->
  Len = size(Value),
  encode_iei(maps:without([sm_rp_ui], Params), <<Tail/binary, (code_param(sm_rp_ui)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_oa := Value0} = Params, Tail) ->
  Value = encode_oa_da(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_oa], Params), <<Tail/binary, (code_param(sm_rp_oa)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_da := Value0} = Params, Tail) ->
  Value = encode_oa_da(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_da], Params), <<Tail/binary, (code_param(sm_rp_da)):8, Len, Value/binary>>);

encode_iei(#{cause := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([cause], Params), <<Tail/binary, (code_param(cause)):8, Len, Value/binary>>);

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

encode_iei(#{msg_ref := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([msg_ref], Params), <<Tail/binary, (code_param(msg_ref)):8, Len, Value/binary>>);

encode_iei(#{sm_rp_cause := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([sm_rp_cause], Params), <<Tail/binary, (code_param(sm_rp_cause)):8, Len, Value/binary>>);

encode_iei(#{alert_reason := Value0} = Params, Tail) ->
  Value = encode_varint(Value0),
  Len = size(Value),
  encode_iei(maps:without([alert_reason], Params), <<Tail/binary, (code_param(alert_reason)):8, Len, Value/binary>>);

encode_iei(#{msisdn := MSISDN0} = Params, Tail) ->
  MSISDN = encode_imsi(MSISDN0, <<>>),
  Len = size(MSISDN) + 1,
  encode_iei(maps:without([msisdn], Params), <<Tail/binary, 16#08, Len, 16#06, MSISDN/binary>>);

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

code_param(imsi) -> 16#01;
code_param(cause) -> 16#02;
code_param(pdp_info_complete) -> 16#04;
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
