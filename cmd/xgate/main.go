// Command xgate is the gate: the part of the estate people log into.
//
// It serves the SSH bastion and its SFTP mediation. A session here
// belongs to a named principal, is recorded, can be made to carry a
// second factor, and is bounded by a policy written in the protocol's
// own terms. None of the internet-facing HTTP machinery is linked into
// it, and neither are the machine-to-machine relays.
//
// Usage:
//
//	xgate -config /etc/xproxy/xgate.yaml
//	xgate -config file.yaml -validate
//	xgate -version
//
// Signals: SIGHUP reloads the configuration, SIGUSR1 reopens log files,
// SIGTERM and SIGINT shut down gracefully.
package main

import (
	"os"

	"github.com/rom/xproxy/internal/daemon"
	_ "github.com/rom/xproxy/internal/kinds/ssh" // listener kind: ssh
	"github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleGate, os.Args[1:])) }
