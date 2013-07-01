enamed
======
This is a (currently unusable) DNS-server implemented in Erlang.
It's a means for me to learn Erlang (and learning more about low
level DNS protocol details is a big plus). Any feedback is welcome.

In it's current shape, it can decode DNS packets and respond to
queries (with the caveat that it only responds with not
implemented to all queries. It does respond with the query's ID,
opcode and question section though...).

With that said, to get it up and running:

    $ make
    $ erl
    1> enamed:start(53535)

And from another shell:

    $ dig @localhost +notcp -p 53535 example.com

And you should see something like this:

    ; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> @localhost -p 53535 +notcp example.com
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOTIMP, id: 55227
    ;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;example.com.			IN	A

    ;; Query time: 22 msec
    ;; SERVER: 127.0.0.1#53535(127.0.0.1)
    ;; WHEN: Fri Jun 28 16:34:41 2013
    ;; MSG SIZE  rcvd: 29

TODO
====
Lots of stuff! Of the top of my head:

* OTP-stuff, make it more resilient and more in line with
  erlang best practices

DNS features
------------

* domain database, have something to respond to queries with
* zonefile support (but let's write that in perl and have it
  output erlang structures or something :-))
 * I should have some erlang data structure representing a
   zone somewhere.
* fragmentation support
* edns
* tcp
* dnssec
* awareness of rrtypes
* DNS UPDATE
* AXFR
* IXFR
