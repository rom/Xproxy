// Command xrelay is the relay: the part of the estate machines talk to.
//
// It serves the SMTP and submission proxy, the MQTT broker front end,
// the FTP proxy, the syslog relay, the Modbus relay and the NTP and NTS
// time gateway. There are no interactive sessions here and no
// recordings; the policy is written in each protocol's own terms, and
// the traffic comes from devices and services rather than from people or
// from the open internet.
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
	_ "github.com/rom/xproxy/internal/kinds/ftp"    // listener kind: ftp
	_ "github.com/rom/xproxy/internal/kinds/iec104" // listener kind: iec104
	_ "github.com/rom/xproxy/internal/kinds/ldap"   // listener kind: ldap
	_ "github.com/rom/xproxy/internal/kinds/modbus" // listener kind: modbus
	_ "github.com/rom/xproxy/internal/kinds/mqtt"   // listener kind: mqtt
	_ "github.com/rom/xproxy/internal/kinds/ntp"    // listener kind: ntp
	_ "github.com/rom/xproxy/internal/kinds/ntske"  // listener kind: ntske
	_ "github.com/rom/xproxy/internal/kinds/smtp"   // listener kind: smtp
	_ "github.com/rom/xproxy/internal/kinds/snmp"   // listener kind: snmp
	_ "github.com/rom/xproxy/internal/kinds/syslog" // listener kind: syslog
	_ "github.com/rom/xproxy/internal/kinds/tftp"   // listener kind: tftp
	"github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleRelay, os.Args[1:])) }
