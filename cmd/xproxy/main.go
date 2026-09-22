// Command xproxy is the edge data plane: the part of the estate that
// faces the internet.
//
// It serves the HTTP and TLS listeners, the forward proxy with its
// interception, MASQUE, the layer 4 relay and the resolver. Everything
// here talks to clients nobody vouched for, which is why it links
// nothing that a person logs into and nothing that a machine hands
// credentials to; those are xgate's and xrelay's.
//
// Usage:
//
//	xproxy -config /etc/xproxy/xproxy.yaml
//	xproxy -config file.yaml -validate
//	xproxy -version
//
// Signals: SIGHUP reloads the configuration, SIGUSR1 reopens log files,
// SIGTERM and SIGINT shut down gracefully.
package main

import (
	"os"

	"github.com/rom/xproxy/internal/daemon"
	_ "github.com/rom/xproxy/internal/kinds/dns"     // listener kind: dns
	_ "github.com/rom/xproxy/internal/kinds/forward" // listener kind: forward
	_ "github.com/rom/xproxy/internal/kinds/http"    // listener kind: http, and the data plane behind it
	_ "github.com/rom/xproxy/internal/kinds/tcp"     // listener kind: tcp
	"github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleEdge, os.Args[1:])) }
