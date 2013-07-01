% vim: ts=2:sw=2:noet:tw=80
% dnslistener.erl: Listen for dns packets.

% Copyright 2013, Olof Johansson <olof@ethup.se>
%
% Copying and distribution of this file, with or without
% modification, are permitted in any medium without royalty
% provided the copyright notice are preserved. This file is
% offered as-is, without any warranty.

-module(enamed).
-export([start/0, start/1, worker/4]).
-include("dnspkt.hrl").

start() ->
	start(53).

start(Port) ->
	% Error handling? Nah... erlang solves it for me :)
	{ok, Socket} = gen_udp:open(Port, [
		binary,
		{active, true}
	]),

	listen_loop(Socket).

listen_loop(Socket) ->
	io:format("Listen loop entered~n"),

	receive
		{udp, Socket, Addr, Port, Packet} ->
			io:format("Got queried! ~p~n", [Addr]),
			spawn(listener, worker, [self(), Addr, Port, Packet]);
		{reply, Addr, Port, Packet} ->
			io:format("Sending reply to ~p~n", [Addr]),
			gen_udp:send(Socket, Addr, Port, Packet);
		WTF ->
			io:format("Got something strange: ~p~n", [WTF])
	end,

	listen_loop(Socket).

worker(PPid, Addr, Port, Pkt) ->
	Dns = dnspkt:decode(Pkt),
	Response = gen_notimpl(Dns),

	PPid ! {reply, Addr, Port, Response}.

gen_notimpl(Dns) ->
	{
		{header, Header},
		{question, Questions},
		{answer, _},
		{auth, _},
		{additional, _}
	} = Dns,

	Id = Header#dns_header.id,
	Opcode = Header#dns_header.opcode,
	Qdcount = Header#dns_header.qdcount,

	dnspkt:encode({
		{header, #dns_header{
			id=Id,
			qr=1, opcode=Opcode, aa=0, rd=0, ra=0,
			rcode=?DNS_RCODE_NOTIMP,
			qdcount=Qdcount
		}},
		{question, Questions},
		{answer, []},
		{auth, []},
		{additional, []}
	}).
