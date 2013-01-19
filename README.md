-------------------------------------------------------------------------------
Liar is a TLS/SSL proxy server that lies about its identity
-------------------------------------------------------------------------------
The situation -

You have a machine that is semi-compromised, you can control its DNS settings
and you can add a certificate to its store, but you don't really know what it's
doing, who it's talking to or what it's saying. I want to stress at this point
that the machine is yours and you have permission to be doing these things
you're doing to it...

Anyway, this machine talks to a variety of servers, it throws out UDP and TCP
traffic, and quite a lot of its comms are performed over TLS/SSL. The servers
it's talking to aren't under your control and you don't have the keys for them.
It may be doing DHE key exchange so even if you did have the keys you can't
just decode captured packet streams with wireshark or other tool. What you need
is a man in the middle.

The solution -

Enter Liar. Liar is a DNS server, except every time a machine asks it for an IP
address Liar brings up a new network interface on the box it runs on, generates
a certificate for the servername that was requested and starts listening on as
many ports as you've told it to, then tells the client that the server is at the
new address that's just come into existence. When a connection is made it makes
a forward connection to the real server, relays traffic and logs everything
that's being said. It can also change data in flight if necessary. It does this
for tcp and udp traffic, and TLS/SSL connections over TCP.

There are probably better ways to achieve much of what's going on here by going
below the transport layer, that may avoid the use of multiple IP addresses and
fake network interfaces, but what the hey, it's the first model I thought of.

It's not *that* clever. It needs you to tell it what's an SSL port what's not.
Detecting this would probably be easy but it's not implemented. It's also not
that well written, this is a hacky side-project and (I would like to stress)
not representative of my enterprise-grade day-job coding.

Liar has only ever been tested on debian linux (ARM and x86_64).

And for any pythonistas out there- if it looks like it was written by a C coder
learning python as he went along... well there's a reason for that :)

Liar is released under the GPLv3 license. At the moment it's all the work of
one man so if the license is an issue and you have a good reason for wanting
it under different terms then let me know and we might be able to work it out
I'll probably just be flattered anyone's interested.

david.hicks@starnose.net
