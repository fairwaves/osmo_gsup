% This Source Code Form is subject to the terms of the Mozilla Public
% License, v. 2.0. If a copy of the MPL was not distributed with this
% file, You can obtain one at https://mozilla.org/MPL/2.0/.
% (C) 2019 Andrey Velikiy <agreat22@gmail.com>
% (C) 2019 Fairwaves (edited) 

-module (ipa_encode_decode_test).

-include_lib("eunit/include/eunit.hrl").

ping_test() ->
  ?assertEqual({reply, ping, <<00,01,16#fe,01>>,<<>>}, ipa:decode(<<00,01,16#fe,00>>)),
  ?assertEqual({reply, ack, <<00,01,16#fe,04>>,<<>>}, ipa:decode(<<00,01,16#fe,06>>)),
  ?assertEqual({reply, resp, <<00,01,16#fe,06>>,<<>>}, ipa:decode(<<00,01,16#fe,05>>)).

more_data_test() ->
  ?assertEqual({more_data, <<00,01,16#fe>>}, ipa:decode(<<00,01,16#fe>>)),
  ?assertEqual({more_data, <<00,06,16#ee,5,1,2>>}, ipa:decode(<<00,06,16#ee,5,1,2>>)).

error_test() ->
  ?assertEqual({error, {bad_stream_id, 255}}, ipa:decode(<<00,01,16#ff,1>>)),
  ?assertEqual({error, {bad_protocol_extension, 1}}, ipa:decode(<<00,01,16#ee,1>>)).

ok_test() ->
  ?assertEqual({ok,{<<1,2,3,4,5>>, <<6,7>>}}, ipa:decode(<<00,06,16#ee,5,1,2,3,4,5,6,7>>)).
