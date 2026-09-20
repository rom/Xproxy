package cluster

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadLine feeds arbitrary bytes to the cluster framing reader. A
// peer inside the mutual TLS boundary can send anything at all, and a
// compromised node is the threat model this reader exists under: it
// must bound what it returns and never grow without limit.
func FuzzReadLine(f *testing.F) {
	f.Add([]byte("hello\n"), 64)
	f.Add([]byte("no newline at all"), 8)
	f.Add(bytes.Repeat([]byte("a"), 1024), 16)
	f.Add([]byte{}, 1)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if limit < 1 || limit > 1<<20 {
			return
		}
		line, err := readLine(bufio.NewReader(bytes.NewReader(data)), limit)
		if err != nil {
			return
		}
		if len(line) > limit {
			t.Fatalf("readLine returned %d bytes for a limit of %d", len(line), limit)
		}
		if bytes.ContainsRune(line, '\n') {
			t.Fatalf("readLine returned a line containing a newline: %q", line)
		}
	})
}
