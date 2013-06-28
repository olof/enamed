-record(dns_header, {
	id,
	qr, opcode, aa, tc, rd, ra, z, rcode,
	qdcount,
	ancount,
	nscount,
	arcount
}).

-record(dns_question, {
	name, type, class
}).

-record(dns_rr, {
	name, type, class, ttl, length, data
}).

% Classes, RFC 1035
-define(DNS_CLASS_IN, 1).
-define(DNS_CLASS_CS, 2).
-define(DNS_CLASS_CH, 3).
-define(DNS_CLASS_HS, 4).

% RR Types, RFC 1035
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
