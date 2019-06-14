% This Source Code Form is subject to the terms of the Mozilla Public
% License, v. 2.0. If a copy of the MPL was not distributed with this
% file, You can obtain one at https://mozilla.org/MPL/2.0/.
% (C) 2019 Andrey Velikiy <agreat22@gmail.com>
% (C) 2019 Fairwaves (edited) 

-module(ipa).

-include ("ipa.hrl").

-export ([decode/1, encode/1]).

-spec decode(binary()) -> {ok, binary()} | {reply, ping | resp | ack, binary(), binary()} | {more_data, binary()} | {error, term()}.
decode(<<1:16, ?IPAC_PROTO_IPACCESS, ?IPAC_MSGT_PING, Rest/binary>>) ->
  {reply, ping, <<1:16, ?IPAC_PROTO_IPACCESS, ?IPAC_MSGT_PONG>>, Rest};

decode(<<1:16, ?IPAC_PROTO_IPACCESS, ?IPAC_MSGT_ID_RESP, Rest/binary>>) ->
  {reply, resp, <<1:16, ?IPAC_PROTO_IPACCESS, ?IPAC_MSGT_ID_ACK>>, Rest};

decode(<<1:16, ?IPAC_PROTO_IPACCESS, ?IPAC_MSGT_ID_ACK, Rest/binary>>) ->
  {reply, ack, <<1:16, ?IPAC_PROTO_IPACCESS, ?IPAC_MSGT_ID_GET>>, Rest};

decode(<<PSize:16, ?IPAC_PROTO_OSMO, Packet:PSize/binary, Rest/binary>>) ->
  case Packet of
    <<?IPAC_PROTO_EXT_GSUP, Packet1/binary>> ->
      {ok, {Packet1, Rest}};
    <<X, _/binary>> ->
      {error, {bad_protocol_extension, X}}
  end;

decode(<<_PSize:16, X, _/binary>>) when X /= ?IPAC_PROTO_OSMO ->
  {error, {bad_stream_id, X}};

decode(Rest) ->
  {more_data, Rest}.

-spec encode(binary()) -> binary().
encode(Packet) ->
  Len = size(Packet) + 1,
  <<Len:16, ?IPAC_PROTO_OSMO, ?IPAC_PROTO_EXT_GSUP, Packet/binary>>.
