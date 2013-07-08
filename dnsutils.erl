% vim: ts=2:sw=2:noet:tw=80
-module(dnsutils).
-export([domain_text/1]).

% dnsutils.erl: Helper functions in dealing with dns data

% Copyright 2013, Olof Johansson <olof@ethup.se>
%
% Copying and distribution of this file, with or without
% modification, are permitted in any medium without royalty
% provided the copyright notice are preserved. This file is
% offered as-is, without any warranty.

-include_lib("eunit/include/eunit.hrl").

% Returns a string representation of a domain:
% "x20.se." = labels_bin2text(<<3:8, "x20", 2:8, "se", 0:8>>)
domain_text(Raw) ->
	domain_text(Raw, []).

domain_text(<<0:8>>, Domain) ->
	Domain ++ ".";
domain_text(Raw, []) ->
	{Label, LabelTail} = extract_label(Raw),
	domain_text(LabelTail, binary_to_list(Label));
domain_text(Raw, Domain) ->
	{Label, LabelTail} = extract_label(Raw),
	domain_text(LabelTail, Domain ++ "." ++ binary_to_list(Label)).

extract_label(Raw) ->
	<<Len:8/integer, LenTail/binary>> = Raw,
	<<Label:Len/binary, LabelTail/binary>> = LenTail,
	{Label, LabelTail}.

domain_text_test_() ->
	[
		?_assertEqual(
			".",
			domain_text(<<0:8>>)
		),
		?_assertEqual(
			"ethup.se.",
			domain_text(<<5:8, "ethup", 2:8, "se", 0:8>>)
		)
	].

