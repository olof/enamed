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

