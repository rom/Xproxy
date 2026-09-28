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

## xrelay — the machines

Machine to machine, and operational technology. No people, no recordings, and a
policy written in each protocol's own terms.

### Mail, messaging and files

| Protocol | Page | Usual port |
|----------|------|------------|
| SMTP and submission | [smtp](smtp.md) | 25, 587, 465 |
| MQTT 3.1.1 and 5.0 | [mqtt](mqtt.md) | 1883, 8883 |
| AMQP 0-9-1 and AMQP 1.0 | [amqp](amqp.md) | 5672, 5671 |
| FTP and FTPS | [ftp](ftp.md) | 21, 990 |
| TFTP | [tftp](tftp.md) | 69 |
| Syslog, RFC 5424 and RFC 3164 | [syslog](syslog.md) | 514, 6514 |

### Infrastructure

| Protocol | Page | Usual port |
|----------|------|------------|
| SNMP v1, v2c and v3 | [snmp](snmp.md) | 161, 162 |
| LDAP v3 and LDAPS | [ldap](ldap.md) | 389, 636 |
| DHCPv4 | [dhcp](dhcp.md) | 67, 68 |
| DHCPv6 | [dhcp6](dhcp6.md) | 547 |
| NTP v1–v4, SNTP, NTS-protected | [ntp](ntp.md) | 123 |
| NTS key establishment | [ntske](ntske.md) | 4460 |

### Databases

| Protocol | Page | Usual port |
|----------|------|------------|
| PostgreSQL frontend/backend v3 | [postgres](postgres.md) | 5432 |
| MySQL and MariaDB | [mysql](mysql.md) | 3306 |
| TDS 7.x for SQL Server | [tds](tds.md) | 1433 |
| Redis, RESP2 and RESP3 | [redis](redis.md) | 6379 |

### Operational technology

The protocols in front of equipment that cannot be patched on a release cycle.
Every one of them was designed for a private network, and none has
authentication worth the name.

| Protocol | Page | Usual port |
|----------|------|------------|
| Modbus/TCP, RTU, ASCII, Modbus/TCP Security | [modbus](modbus.md) | 502, 802 |
| IEC 60870-5-104, IEC 62351-3 TLS | [iec104](iec104.md) | 2404 |
| BACnet/IP (ASHRAE 135 Annex J) | [bacnet](bacnet.md) | 47808 |
| Siemens S7comm | [s7](s7.md) | 102 |

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
