---------------------------------------------------------------
Liar is an SSL proxy server that lies about its identity
---------------------------------------------------------------
The idea behind liar is this -

You have a machine that is semi-compromised, you can control its
DNS setting and you can add a certificate to the store, but you
don't really know what it's doing, who it's talking to or what it's
saying. It may be doing DHE key exchange so you can't just decode
captured packet streams with wireshark or other tool. What you
need is a man in the middle.

Liar is run on a linux box, it pretends to be a DNS server, but
every time a DNS request is made it brings up a new IP interface
on the machine, and gives this IP address as the DNS response. At
the same time it generates a new certificate for that server and
opens up a bunch of (user specified) ports, some listening for
SSL/TLS connections, some plaintext. When a new connection is made
liar connects to the real server and proxies all traffic back and
forward, logging everything that occurs.
