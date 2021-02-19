#!/usr/local/lib/erlang23/bin/escript

% using info from https://www.chrisdcmoore.co.uk/post/tplink-easy-smart-switch-vulnerabilities/

-define(KEY, <<"Ei2HNryt8ysSdRRI54XNQHBEbOIRqNjQgYxsTmuW3srSVRVFyLh8mwvhBLPFQph3ecDMLnDtjDUdrUwt7oTsJuYl72hXESNiD6jFIQCtQN1unsmn3JXjeYwGJ55pqTkVyN2OOm3vekF6G1LM4t3kiiG4lGwbxG4CG1s5Sli7gcINFBOLXQnPpsQNWDmPbOm74mE7eyR3L7tk8tUhI17FLKm11hrrd1ck74bMw3VYSK3X5RrDgXelewMU6o1tJ3iX">>).
-define(CLIENT_PORT, 29809).
-define(SERVER_PORT, 29808).

-define(PORT_STATISTICS, 16384).


main(["observe"]) ->
	application:start(crypto),
	{ok, _Port1} = gen_udp:open(?CLIENT_PORT, [{active, true}, binary]),
	{ok, _Port2} = gen_udp:open(?SERVER_PORT, [{active, true}, binary]),
	recv(true);

main([RawAddress]) ->
	application:start(crypto),
	% key from https://github.com/janisstreib/tp-link-intercept

	Parsed = parse_mac(RawAddress),

	Seq = crypto:strong_rand_bytes(2),

	PlainPacket = <<1, 1, Parsed/binary, 16#02_0b_ad_0b_ad_00:48, Seq/binary, 0:32,
		   40:16, 0:16, 0:16, Seq/binary, 0:32, ?PORT_STATISTICS:16, 0:16, 16#FFFF0000:32>>,
	CipherPacket = crypto:crypto_one_time(rc4, ?KEY, PlainPacket, true),
	%io:format("~w, ~w~n", [PlainPacket, CipherPacket]),

	{ok, Port} = gen_udp:open(?CLIENT_PORT, [{active, true}, binary]),
	ok = gen_udp:send(Port, {{255,255,255,255}, ?SERVER_PORT}, CipherPacket),

	recv(false);
main([]) -> usage().

recv(Continue) ->
	receive
		{udp, _Socket, _IP, _Port, Resp} ->
			PlainResp = crypto:crypto_one_time(rc4, ?KEY, Resp, true),
			<<_Version, _PacketType, _SwitchMac:6/binary, _ClientMac:6/binary,
			  _Seq:16, _Error:32, Length:16,
			  _Frag:16, 0:16, _Token:16, 0:32,
			  Payload:(Length - 36)/binary, 16#FFFF0000:32>> =
			  PlainResp,

			%io:format("Ver ~B, Type ~B, switch ~w, client ~s, "
			%	  "seq ~B, error ~B, Frag ~B, "
                        %          "Token ~B, Payload ~w~n", [Version,
                        %          PacketType, SwitchMac, ClientMac, Seq,
                        %          Error, Frag, Token, Payload]),
			decode_payload(Payload),
			io:format("~n"),
			case Continue of
				true -> recv(Continue);
				false -> ok
			end;
		Other ->
			io:format("~w~n", [Other]),
			recv(Continue)
	after 15000 ->
		ok
	end.

decode_payload(<<Type:16, Length:16, Data:Length/binary, Rest/binary>>) ->
	print_payload(Type, Data),
	decode_payload(Rest);
decode_payload(<<>>) -> ok.

link_status(0) -> down;
link_status(5) -> '100MFull';
link_status(6) -> '1000MFull';
link_status(S) -> integer_to_list(S).


print_payload(?PORT_STATISTICS, <<PortNumber, Enable, Link, TxGood:32, TxBad:32, RxGood:32, RxBad:32>>) ->
	io:format("  port-stat ~B, enable ~B, link_status ~s, txgood ~B, txbad ~B, rxgood ~B, rxbad ~B~n",
                  [PortNumber, Enable, link_status(Link), TxGood, TxBad, RxGood, RxBad]);
print_payload(Type, Data) ->
	io:format("  Type ~B, ~w~n", [Type, Data]).

parse_mac(Address) ->
	{ok, Out, _} = io_lib:fread("~16u:~16u:~16u:~16u:~16u:~16u", Address),
	list_to_binary(Out).

usage() ->
	io:format("foo AA:BB:CC:DD:EE:FF~n", []).
