package proxy

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

const testRules = `
rule secret_marker : exfiltration {
  meta:
    description = "a marker that must not leave"
  strings:
    $a = "TOP-SECRET-MARKER"
  condition:
    $a
}

rule pe_header : malware {
  strings:
    $mz = { 4D 5A 90 00 }
  condition:
    $mz
}
`

func rulesFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(p, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// echoServer answers whatever it is sent, and can also speak first.
func echoServer(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
