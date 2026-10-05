# The protocols

One page per listener kind: what the protocol is on the wire, what security it
was designed with, what this proxy decided to read, and what it deliberately
does not do.

These pages are the introduction. The settings are in
[docs/CONFIG.md](../CONFIG.md), the code layout is in
[docs/ARCHITECTURE.md](../ARCHITECTURE.md), and the conformance table for the
HTTP side is [docs/RFC.md](../RFC.md).

Every page has the same five sections, in the same order, because the order is
what a reader needs: the protocol before the policy, and the policy before the
reference.

## xproxy — the edge

The internet-facing data plane: HTTP and TLS, the forward proxy, DNS, and the
two generic layer 4 relays.

| Protocol | Page | Usual port |
|----------|------|------------|
| HTTP/1.1, HTTP/2, HTTP/3 | [http](http.md) | 80, 443 |
| TLS and QUIC passthrough | [tcp](tcp.md) | any |
| Any datagram protocol | [udp](udp.md) | any |
| CONNECT, SOCKS5, MASQUE, TLS interception | [forward](forward.md) | 3128, 8080 |
| DNS over UDP, TCP, TLS, HTTPS and QUIC | [dns](dns.md) | 53, 853 |

## xgate — the people

Interactive access by named principals. Sessions here are recorded, can require
a second factor, and the credential that opens the far end is the gate's rather
than the person's.

| Protocol | Page | Usual port |
|----------|------|------------|
| SSH and SFTP | [ssh](ssh.md) | 22 |
| Telnet (RFC 854 NVT) | [telnet](telnet.md) | 23 |
| RFB 3.3–3.8, VeNCrypt | [vnc](vnc.md) | 5900+ |
| RDP over TLS, NLA, or its own encryption | [rdp](rdp.md) | 3389 |

## xrelay — the services

Machine to machine, between services. No people, no recordings, and a policy
written in each protocol's own terms.

### Mail, messaging and files

| Protocol | Page | Usual port |
|----------|------|------------|
| SMTP and submission | [smtp](smtp.md) | 25, 587, 465 |
| AMQP 0-9-1 and AMQP 1.0 | [amqp](amqp.md) | 5672, 5671 |
| FTP and FTPS | [ftp](ftp.md) | 21, 990 |

### Directory and databases

| Protocol | Page | Usual port |
|----------|------|------------|
| LDAP v3 and LDAPS | [ldap](ldap.md) | 389, 636 |
| PostgreSQL frontend/backend v3 | [postgres](postgres.md) | 5432 |
| MySQL and MariaDB | [mysql](mysql.md) | 3306 |
| TDS 7.x for SQL Server | [tds](tds.md) | 1433 |
| Redis, RESP2 and RESP3 | [redis](redis.md) | 6379 |

### The mailbox protocols

[SMTP](smtp.md) above is a message on its way out, and can be decided about one
message at a time. These two are the other half of mail: a client with a
credential asking for everything that ever arrived, where the access is
legitimate and the *volume* is the signal.

| Protocol | Page | Usual port |
|----------|------|------------|
| IMAP4rev2 and IMAP4rev1, with STARTTLS | [imap](imap.md) | 143, 993 |
| POP3, with STLS | [pop3](pop3.md) | 110, 995 |

This is where `max_fetch_messages` and `max_retr_bytes` live: the settings that
tell a mail client's first synchronisation apart from an emptied account, which
nothing in a mail server's own log does.

### Authentication, authorisation and accounting

The protocols that decide who may get onto the network and who may change the
equipment. All three carry credentials, and on two of them the relay holds the
shared secret -- which is what makes a policy here worth more than a packet
filter's.

| Protocol | Page | Usual port |
|----------|------|------------|
| RADIUS, with EAP and dynamic authorization | [radius](radius.md) | 1812, 1813, 3799 |
| TACACS+ (RFC 8907), and over TLS | [tacacs](tacacs.md) | 49 |
| Kerberos over HTTPS (MS-KKDCP) | [kkdcp](kkdcp.md) | 443 |

RADIUS and TACACS+ are linked into **xot** as well, because a plant's switches,
routers and firewalls authenticate their administrators the same way a data
centre's do -- and on a TACACS+ listener the work orders a configuration command
is matched against live there. The KDC proxy is **xproxy**'s by default,
because MS-KKDCP exists so that a client outside the network can reach a KDC
inside it: `daemon: xrelay` puts it on the relay for an estate that runs one
internally.

## xot — the plant

The protocols in front of equipment that cannot be patched on a release cycle.
Every one of them was designed for a private network, and none has
authentication worth the name — which is why the relay *is* the access control
here, and why it is a binary that holds these protocols and nothing else.

| Protocol | Page | Usual port |
|----------|------|------------|
| Modbus/TCP, RTU, ASCII, Modbus/TCP Security | [modbus](modbus.md) | 502, 802 |
| IEC 60870-5-104, IEC 62351-3 TLS | [iec104](iec104.md) | 2404 |
| Siemens S7comm | [s7](s7.md) | 102 |
| IEC 61850 MMS | [mms](mms.md) | 102 |
| BACnet/IP (ASHRAE 135 Annex J) | [bacnet](bacnet.md) | 47808 |
| OPC UA | [opcua](opcua.md) | 4840 |
| CoAP, and CoAP over DTLS | [coap](coap.md) | 5683, 5684 |

## xrelay and xot — the infrastructure both run

Time, provisioning, logging and monitoring. A data centre runs these and so does
a plant, so both binaries link them and the listener says which daemon binds it:
`daemon: xot`, defaulting to `xrelay`.

| Protocol | Page | Usual port |
|----------|------|------------|
| MQTT 3.1.1 and 5.0, with Sparkplug B | [mqtt](mqtt.md) | 1883, 8883 |
| Syslog, RFC 5424 and RFC 3164 | [syslog](syslog.md) | 514, 6514 |
| SNMP v1, v2c and v3 | [snmp](snmp.md) | 161, 162 |
| TFTP | [tftp](tftp.md) | 69 |
| DHCPv4 | [dhcp](dhcp.md) | 67, 68 |
| DHCPv6 | [dhcp6](dhcp6.md) | 547 |
| NTP v1–v4, SNTP, NTS-protected | [ntp](ntp.md) | 123 |
| NTS key establishment | [ntske](ntske.md) | 4460 |

## Reading these pages

Two sections are worth knowing about before you start.

**"What the protocol gives you"** is where the page says what the protocol's own
security is actually worth. For several of these the honest answer is nothing at
all, and the page says so rather than describing an authentication mechanism
nobody deploys.

**"What it does not do"** is the section to read before relying on a listener.
It names the client list that is only an address list on UDP, the segment a
listener is not a firewall for, the negotiation that is refused rather than
rewritten, and the content that is bounded rather than inspected. A page that
only said what a listener decides would read as a claim to cover a protocol.
