% vim: ts=2:sw=2:noet:tw=80

% Copyright 2013, Olof Johansson <olof@ethup.se>
%
% Copying and distribution of this file, with or without
% modification, are permitted in any medium without royalty
% provided the copyright notice are preserved. This file is
% offered as-is, without any warranty.

%% Opcodes
% RFC 1035
-define(DNS_OPCODE_QUERY, 0).
-define(DNS_OPCODE_IQUERY, 1).
-define(DNS_OPCODE_STATUS, 2).

%% Rcodes
% RFC 1035
-define(DNS_RCODE_NOERROR, 0).
-define(DNS_RCODE_FORMERR, 1).
-define(DNS_RCODE_SERVFAIL, 2).
-define(DNS_RCODE_NXDOMAIN, 3).
-define(DNS_RCODE_NOTIMP, 4).
-define(DNS_RCODE_REFUSED, 5).
% RFC 2136
-define(DNS_RCODE_YXDOMAIN, 6).
-define(DNS_RCODE_YXRRSET, 7).
-define(DNS_RCODE_NXRRSET, 8).
-define(DNS_RCODE_NOTAUTH, 9).
-define(DNS_RCODE_NOTZONE, 10).

%% Classes
% RFC 1035
-define(DNS_CLASS_IN, 1).
-define(DNS_CLASS_CS, 2).
-define(DNS_CLASS_CH, 3).
-define(DNS_CLASS_HS, 4).

%% RR Types
% RFC 1035
-define(DNS_RR_A, 1).
-define(DNS_RR_NS, 2).
-define(DNS_RR_MD, 3).
-define(DNS_RR_MF, 4).
-define(DNS_RR_CNAME, 5).
-define(DNS_RR_SOA, 6).
-define(DNS_RR_MB, 7).
-define(DNS_RR_MG, 8).
-define(DNS_RR_MR, 9).
-define(DNS_RR_NULL, 10).
-define(DNS_RR_WKS, 11).
-define(DNS_RR_PTR, 12).
-define(DNS_RR_HINFO, 13).
-define(DNS_RR_MX, 15).
-define(DNS_RR_TXT, 16).

-record(dns_header, {
	id,
	qr=0, opcode=1, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0,
	qdcount=0,
	ancount=0,
	nscount=0,
	arcount=0
}).

-record(dns_question, {
	name, type, class=?DNS_CLASS_IN
}).

-record(dns_rr, {
	name, type, class=?DNS_CLASS_IN, ttl, length, data
}).
