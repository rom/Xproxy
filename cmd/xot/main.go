// Command xot is the OT daemon: the part of the estate the plant talks
// to.
//
// It serves the control protocols -- Modbus, IEC 60870-5-104, S7,
// IEC 61850 MMS, BACnet/IP, OPC UA and CoAP -- and the protocols the
// field equipment itself speaks: SNMP, TFTP, DHCP and DHCPv6, syslog,
// the NTP and NTS time gateway, and MQTT for Sparkplug B telemetry.
// Nothing else is linked into it. A mail parser, an FTP proxy, a
// directory and the database wire protocols are code this binary does
// not contain, which is the whole reason it is a binary of its own: it
// is the one that sits at level 3.5, between the plant and everything
// else, and what it links is what an attack there has to work with.
//
// The eight protocols both estates run -- syslog, SNMP, TFTP, DHCP,
// DHCPv6, NTP, NTS and MQTT -- belong to xrelay unless a listener says
// `daemon: xot`, so a configuration written before this daemon existed
// means what it meant.
//
// Usage:
//
//	xot -config /etc/xproxy/xot.yaml
//	xot -config file.yaml -validate
//	xot -version
//
// Signals: SIGHUP reloads the configuration, SIGUSR1 reopens log files,
// SIGTERM and SIGINT shut down gracefully.
package main

import (
	"os"

	"github.com/rom/xproxy/internal/daemon"
	_ "github.com/rom/xproxy/internal/kinds/bacnet" // listener kind: bacnet
	_ "github.com/rom/xproxy/internal/kinds/coap"   // listener kind: coap
	_ "github.com/rom/xproxy/internal/kinds/dhcp"   // listener kind: dhcp
	_ "github.com/rom/xproxy/internal/kinds/dhcp6"  // listener kind: dhcp6
	_ "github.com/rom/xproxy/internal/kinds/iec104" // listener kind: iec104
	_ "github.com/rom/xproxy/internal/kinds/mms"    // listener kind: mms
	_ "github.com/rom/xproxy/internal/kinds/modbus" // listener kind: modbus
	_ "github.com/rom/xproxy/internal/kinds/mqtt"   // listener kind: mqtt
	_ "github.com/rom/xproxy/internal/kinds/ntp"    // listener kind: ntp
	_ "github.com/rom/xproxy/internal/kinds/ntske"  // listener kind: ntske
	_ "github.com/rom/xproxy/internal/kinds/opcua"  // listener kind: opcua
	_ "github.com/rom/xproxy/internal/kinds/radius" // listener kind: radius
	_ "github.com/rom/xproxy/internal/kinds/s7"     // listener kind: s7
	_ "github.com/rom/xproxy/internal/kinds/snmp"   // listener kind: snmp
	_ "github.com/rom/xproxy/internal/kinds/syslog" // listener kind: syslog
	_ "github.com/rom/xproxy/internal/kinds/tacacs" // listener kind: tacacs
	_ "github.com/rom/xproxy/internal/kinds/tftp"   // listener kind: tftp
	"github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleOT, os.Args[1:])) }
