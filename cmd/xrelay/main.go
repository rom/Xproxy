// Command xrelay is the relay: the part of the estate machines talk to.
//
// It serves the SMTP and submission proxy, the FTP proxy, LDAP, the
// database wire protocols, AMQP, the two authentication protocols the
// network equipment speaks -- RADIUS and TACACS+ -- the Kerberos KDC
// proxy where an estate runs one inside its own network, and -- where a
// listener does not hand them to xot -- the MQTT broker front end, the
// syslog relay, SNMP, TFTP, DHCP and the NTP and NTS time gateway. There are no
// interactive sessions here and no recordings; the policy is written in
// each protocol's own terms, and the traffic comes from services rather
// than from people or from the open internet.
//
// The plant's own protocols are not here. Modbus, IEC 60870-5-104, S7,
// IEC 61850 MMS, BACnet/IP, OPC UA and CoAP are xot's, for the reason
// this daemon is not xproxy: what a binary links is what an attack on
// it has to work with, and the proxy in front of a process network
// should not carry a mail parser.
//
// Usage:
//
//	xrelay -config /etc/xproxy/xrelay.yaml
//	xrelay -config file.yaml -validate
//	xrelay -version
//
// Signals: SIGHUP reloads the configuration, SIGUSR1 reopens log files,
// SIGTERM and SIGINT shut down gracefully.
package main

import (
	"os"

	"github.com/rom/xproxy/internal/daemon"
	_ "github.com/rom/xproxy/internal/kinds/amqp"     // listener kind: amqp
	_ "github.com/rom/xproxy/internal/kinds/dhcp"     // listener kind: dhcp
	_ "github.com/rom/xproxy/internal/kinds/dhcp6"    // listener kind: dhcp6
	_ "github.com/rom/xproxy/internal/kinds/ftp"      // listener kind: ftp
	_ "github.com/rom/xproxy/internal/kinds/imap"     // listener kind: imap
	_ "github.com/rom/xproxy/internal/kinds/kkdcp"    // listener kind: kkdcp
	_ "github.com/rom/xproxy/internal/kinds/ldap"     // listener kind: ldap
	_ "github.com/rom/xproxy/internal/kinds/mqtt"     // listener kind: mqtt
	_ "github.com/rom/xproxy/internal/kinds/mysql"    // listener kind: mysql
	_ "github.com/rom/xproxy/internal/kinds/ntp"      // listener kind: ntp
	_ "github.com/rom/xproxy/internal/kinds/ntske"    // listener kind: ntske
	_ "github.com/rom/xproxy/internal/kinds/pop3"     // listener kind: pop3
	_ "github.com/rom/xproxy/internal/kinds/postgres" // listener kind: postgres
	_ "github.com/rom/xproxy/internal/kinds/radius"   // listener kind: radius
	_ "github.com/rom/xproxy/internal/kinds/redis"    // listener kind: redis
	_ "github.com/rom/xproxy/internal/kinds/smtp"     // listener kind: smtp
	_ "github.com/rom/xproxy/internal/kinds/snmp"     // listener kind: snmp
	_ "github.com/rom/xproxy/internal/kinds/syslog"   // listener kind: syslog
	_ "github.com/rom/xproxy/internal/kinds/tacacs"   // listener kind: tacacs
	_ "github.com/rom/xproxy/internal/kinds/tds"      // listener kind: tds
	_ "github.com/rom/xproxy/internal/kinds/tftp"     // listener kind: tftp
	"github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleRelay, os.Args[1:])) }
