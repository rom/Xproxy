package testutil

import (
	"io"
	"net"
	"testing"
)

// EchoServer answers whatever it is sent, and can also speak first. It
// is the far side of every relay test: what comes back tells the test
// what the proxy passed on, and a greeting exercises the case where the
// upstream, not the client, opens the conversation.
func EchoServer(t *testing.T, greeting string) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if greeting != "" {
					_, _ = io.WriteString(c, greeting)
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}
