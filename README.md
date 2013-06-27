enamed
======
This is a (currently unusable) DNS-server implemented in Erlang.
It's a means for me to learn Erlang (and learning more about low
level DNS protocol details is a big plus). Any feedback is welcome.

In it's current shape, it can decode DNS packets and respond to
queries (with the caveat that it only responds with not
implemented to all queries. It does respond with the query's ID
and opcode though...).

With that said, to get it up and running:

    $ make
    $ erl
    1> listener:start(5353)

And from another shell:

    $ dig @127.0.0.1 +notcp -p 5353 example.com

And you should see something like this:

    ; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> @127.0.0.1 +notcp -p 5353 example.com
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOTIMP, id: 64923
    ;; flags: qr; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

    ;; Query time: 0 msec
    ;; SERVER: 127.0.0.1#5353(127.0.0.1)
    ;; WHEN: Thu Jun 27 21:47:53 2013
    ;; MSG SIZE  rcvd: 12

TODO
====
Lots of stuff! Of the top of my head:

* OTP-stuff, make it more resilient and more in line with
  erlang best practices
* DNS packet encoding (I don't like the hardcoding dns packets i
  do now)

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
