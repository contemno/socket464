# Summary

The goal of this project is to facilitate running an IPv6-only local network while preserving access to the IPv4 Internet, instead having to resort to running a
'dual stack' configuration of both IPv4 and IPv6. This project is a 'shim'
library that is preloaded by a target application to translate IPv4 to IPv6
transparently to the application.

If an application attempts to create a connection to an IPv4 destination, this
library will intercept the call and translate it to an IPv6 destination. The
packets will then be translated back from IPv6 to IPv4 at a NAT64 device. For
home users, the NAT64 device will be their sole router connecting their home
network to the internet. For enterprise environments the placement of the NAT64
function is more flexible.

Eventually the goal is to incorporate this functionality into the Linux kernel.

## Running single-stack with IPv6

As the world slowly transitions to IPv6 there are various challenges that impede
progress. Fortunately there are tools to ease that transition, such as
running both IPv4 and IPv6 simultaneously in a dual-stack configuration.
Running dual-stack has it's own operational overhead as essentially you're
running two networks.

Another option that has been recently made possible is running IPv6 only, while
translating to IPv4 at the edge when accessing the IPv4 global internet. This
has been made possible by the intrduction of DNS64 and NAT64, for the creation
of synthetic AAAA records and translation of IPv6 headers to IPv4 headers, respectively. DNS64 and NAT64 work together to facilitate traffic destined to the IPv4 internet,
over the IPv6-only local network.

If there are no AAAA records for a given FQDN, DNS64 creates a sythetic AAAA
record from the A records for that FQDN. The synthetic AAAA records are constructed
from the IPv4 address, and prepending the PREF64 prefix; either a configured
from the orgs public IPv6 space, or using the Well Known Prefix (WKP) 64:ff9b::/96.

Then the device configured for NAT64, either in the path or one-armed, translates
IPv6 packets destined to the PREF64 prefix by extracting the original IPv4 address
from the lower 32 bits. The NAT64 device also translates the source to an IPv4
address from a pool of addresses. To increase the scalability the NAT64 device
is also performing Port Address Translation (PAT).

## We're done, right? Solved IPv4 exhaustion? No, unfortunately.

There are a couple edge cases that are not addressed by those tools.

- IPv4 only applications -- Applications only able to open IPv4 sockets. Fortunately
  most web browsers don't have this issue.

- IPv4 literals -- Web and local applications that retreive IPv4 address information
  from sources other than the local DNS64 server; such as DNS over HTTPS,
  DNS over TLS, web API, or have have IPv4 address information directly embedded.
  In this case, DNS64 doesn't have an opportunity to see the IPv4 to construct
  the synthetic AAAA records.

Fortunately there is another tool: XLAT464. This process is fairly straight forward;
it simply copies the translation mechanism that normally occurs in DNS64 to create
synthetic AAAA records. It's usually implemented as a system process that creates
a virtual tunnel which appears as a IPv4 connection. Traffic that traverses this
tunnel is translated using the same PREF64 prefix.

XLAT464 is already widely used in the mobile network space. Major providers were
reaching the limits of private IPv4 space (RFC1918) and resorted to 'squatting'
on historically non-advertised IPv4 space, such as the US DOD's 22.0.0.0/8. While
the major providers were not advertising this space to the global Internet, it was
problematic because the US DOD could choose at any point to use or sell the
address space. This would cause issues for their customers attempting to access
resources only accessible via that address space.

Unfortunetly, XLAT464 support outside of mobile devices is limited. Computer
operating systems range from zero compatibility, buggy implementations, selective
activation, or don't have the components installed by default.

This project aims to be a proof of concept for implementing XLAT464 into into the
operating system without the use of a virutal tunnel interface, and without modifying
client applications. This is implemented as a ld preload library to intercept
libc calls related to sockets. When the library is preloaded on process execution,
various functions are exported with the same name as their libc counterparts. When
the application attempts to call socket functions, they are intercepted and translated
from IPv4 to IPv6. So in essence, the client application still believes it is
communicating over IPv4, when in fact IPv6 is transporting the data. Therefor all
communication within the local network is being transported over IPv6. Communication
to and from the IPv4 Internet are being translated twice; once by the local host
and also by the NAT64 device near the edge of the network. This method has minimal
overhead because the translation happens only once during the creation of the connection.
As a result, the traffic doesn't need to be translated on packet by packet basis
because the socket is originating the traffic natively with IPv6.

This largely works transparently for the client application because the same functions
are used to read and write data to IPv4 and IPv6 sockets. There are ancilary functions
that can provide meta data about the socket and connection, so this data needs to
be transformed as well.

## Planned functionality

- Change socket call to incorporate a check for any non local (127/8) routes in table, if there is, return a AF_INET socket. (see edge cases)

- Get PREF64 prefix from IPv6 RA option

- Use the socket2 crate. Reasons include:
  - Could use Rust-native structs, would not have to use C structs to pass to the functions
  - reduce the amount of 'unsafe' code

## Recommended changes to the kernel socket API

- Create combined socket struct for both AF_INET and AF_INET6, that would silently ignore incompatible INET options if transporting over INET6

## Edge cases

- binding to specific physical interface: weird, because there may not be any interfaces configured with an IPv4 address. Options include:

  - Bind to all configured IPv6 addresses (e.g. tcp[::]:443 or udp[::]:53)
  - Create a fake list of local IPv4 addresses that correspond 1:1 to physical interfaces from IANA reserved space so not to confuse anyone (any more than necessary)
  - fail, "port in use" or some other error

- Connecting to private/reserved IPv4 address space, because it's not publically routable.Options include:

  - If provided XLAT464/NAT64 prefix is not WKP, and publically routable, transform as usual for private and public routable IPv4 space
  - Fail, "no route to host" or some other error

- multicast/broadcast, Options include:

  - transform to equivilent IPv6 mcast group, if one exist

- localhost (127.0.0.0/8). the obvious case for 127.0.0.1 is to transform, but the remaining space is not clear. Options include:
  - transform all 127.0.0.0/8 to ::1
  - fail, "port in use" or "no route to host"

## Example wget run

```UST_BACKTRACE=full LD_PRELOAD=./libsock464.so wget -S --max-redirect 5 --header='Host: slashdot.org' http://104.18.28.86/ -O /dev/null
--2023-03-10 12:01:00--  http://104.18.28.86/
[sock464][debug] called getaddrinfo
Connecting to 104.18.28.86:80...
[sock464][debug] Called socket(2, 1, 0)
[sock464][debug]  Mapped socket(10, 1, 0)
[sock464][debug] Returning socket FD 4
[sock464][debug] Called connect(4, 0x7ffc590efc40, 16)
[sock464][debug][connect] Match AF_INET
[sock464][debug] Mapping AF_INET
[sock464][debug] Original sockaddr_in 104.18.28.86:80
[sock464][debug] called getaddrinfo
[sock464][debug] NAT64 prefix from 'ipv4only.arpa.' [64:ff9b::c000:aa]
[sock464][debug] Mapped sockaddr_in6 [64:ff9b::6812:1c56]:80
connected.
HTTP request sent, awaiting response...
HTTP/1.1 301 Moved Permanently
Date: Fri, 10 Mar 2023 17:01:00 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive
Location: https://slashdot.org/
CF-Cache-Status: DYNAMIC
Server: cloudflare
CF-RAY: 7a5d1dfeead0b0b7-ATL
alt-svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
Location: https://slashdot.org/ [following]
--2023-03-10 12:01:00--  https://slashdot.org/
Resolving slashdot.org (slashdot.org)... [sock464][debug] called getaddrinfo
64:ff9b::6812:1c56, 64:ff9b::6812:1d56, 104.18.29.86, ...
Connecting to slashdot.org (slashdot.org)|64:ff9b::6812:1c56|:443...
[sock464][debug] Called socket(10, 1, 0)
[sock464][debug]  Mapped socket(10, 1, 0)
[sock464][debug] Returning socket FD 5
[sock464][debug] Called connect(5, 0x7ffc590efc40, 28)
[sock464][debug][connect] Match AF_INET6
[sock464][debug] Unmapped sockaddr_in6 [64:ff9b::6812:1c56]:443
connected.
[sock464][debug]Caught setsockopt(5, 6, 31, 0x7eff1b72cdf5, 4)
HTTP request sent, awaiting response...
HTTP/1.1 200 OK
Date: Fri, 10 Mar 2023 17:01:00 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
slash_log_data: shtml
cache-control: no-cache
pragma: no-cache
x-frame-options: SAMEORIGIN
content-security-policy: frame-ancestors 'self'; upgrade-insecure-requests
x-xrds-location: https://slashdot.org/slashdot.xrds
strict-transport-security: max-age=31536000
CF-Cache-Status: DYNAMIC
Server: cloudflare
CF-RAY: 7a5d1e000873e77f-ATL
alt-svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
Length: unspecified [text/html]
Saving to: ‘/dev/null’

/dev/null                              [ <=>                                                          ] 144.16K  --.-KB/s    in 0.02s

2023-03-10 12:01:00 (7.29 MB/s) - ‘/dev/null’ saved [147624]
```