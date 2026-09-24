// Command xrelay is the relay: the part of the estate machines talk to.
//
// It serves the SMTP and submission proxy, the MQTT broker front end,
// the FTP proxy, the syslog relay and the Modbus relay. There are no
// interactive sessions here and no recordings; the policy is written in
// each protocol's own terms, and the traffic comes from devices and
// services rather than from people or from the open internet.
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
	_ "github.com/rom/xproxy/internal/kinds/modbus" // listener kind: modbus
	_ "github.com/rom/xproxy/internal/kinds/mqtt"   // listener kind: mqtt
	_ "github.com/rom/xproxy/internal/kinds/smtp"   // listener kind: smtp
	_ "github.com/rom/xproxy/internal/kinds/syslog" // listener kind: syslog
	"github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleRelay, os.Args[1:])) }
