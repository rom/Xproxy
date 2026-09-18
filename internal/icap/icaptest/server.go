// Package icaptest is a minimal ICAP server for tests: OPTIONS, REQMOD and
// RESPMOD with preview. Behaviour is selected by the encapsulated request
// path (/virus, /modify, /rewrite, /error, /hang) or a body containing
// EICAR.
package icaptest

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Server is the fake ICAP server.
type Server struct {
	ln         net.Listener
	preview    int
	Mu         sync.Mutex
	Requests   []string // methods seen
	Bodies     []string
	Previews   int
	CloseAfter bool
}

func New(t testing.TB, preview int) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &Server{ln: ln, preview: preview}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *Server) URL() string { return "icap://" + f.ln.Addr().String() + "/scan" }

func (f *Server) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		method := strings.Fields(line)[0]
		hdr := http.Header{}
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			if l == "" {
				break
			}
			k, v, _ := strings.Cut(l, ":")
			hdr.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
		f.Mu.Lock()
		f.Requests = append(f.Requests, method)
		f.Mu.Unlock()
		if method == "OPTIONS" {
			fmt.Fprintf(c, "ICAP/1.0 200 OK\r\nMethods: REQMOD, RESPMOD\r\nISTag: \"tag-1\"\r\nAllow: 204\r\nPreview: %d\r\nEncapsulated: null-body=0\r\n\r\n", f.preview)
			continue
		}
		// Read encapsulated header blocks by offsets.
		enc := hdr.Get("Encapsulated")
		var offs []int
		names := []string{}
		for _, p := range strings.Split(enc, ",") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			n, _ := strconv.Atoi(v)
			offs = append(offs, n)
			names = append(names, k)
		}
		var blocks [][]byte
		for i := 0; i+1 < len(offs); i++ {
			blk := make([]byte, offs[i+1]-offs[i])
			io.ReadFull(r, blk)
			blocks = append(blocks, blk)
		}
		hasBody := strings.Contains(enc, "-body=") && !strings.Contains(enc, "null-body")
		var body []byte
		if hasBody {
			// Read chunks until a zero chunk; handle preview then continue.
			readChunks := func() (data []byte, ieof bool) {
				for {
					sizeLine, _ := r.ReadString('\n')
					sizeLine = strings.TrimRight(sizeLine, "\r\n")
					size, ext, _ := strings.Cut(sizeLine, ";")
					n, _ := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
					if n == 0 {
						r.ReadString('\n') // trailing CRLF
						return data, strings.Contains(ext, "ieof")
					}
					chunk := make([]byte, n)
					io.ReadFull(r, chunk)
					r.ReadString('\n')
					data = append(data, chunk...)
				}
			}
			body, _ = readChunks()
			if hdr.Get("Preview") != "" {
				f.Mu.Lock()
				f.Previews++
				f.Mu.Unlock()
				// Decide on the preview: bodies starting with "EICAR" are
				// blocked right away, others need the rest.
				if bytes.HasPrefix(body, []byte("EICAR")) {
					f.block(c)
					continue
				}
				fmt.Fprintf(c, "ICAP/1.0 100 Continue\r\n\r\n")
				rest, _ := readChunks()
				body = append(body, rest...)
			}
		}
		f.Mu.Lock()
		f.Bodies = append(f.Bodies, string(body))
		f.Mu.Unlock()
		reqLine := ""
		if len(blocks) > 0 {
			reqLine = strings.SplitN(string(blocks[0]), "\r\n", 2)[0]
		}
		switch {
		case bytes.Contains(body, []byte("EICAR")) || strings.Contains(reqLine, "/virus"):
			f.block(c)
		case strings.Contains(reqLine, "/modify") && method == "REQMOD":
			// Modified request: add a header, replace the body.
			newHdr := "GET /modified HTTP/1.1\r\nHost: example.test\r\nX-Scanned: yes\r\n\r\n"
			newBody := "clean"
			fmt.Fprintf(c, "ICAP/1.0 200 OK\r\nISTag: \"tag-1\"\r\nEncapsulated: req-hdr=0, req-body=%d\r\n\r\n%s", len(newHdr), newHdr)
			cw := httputil.NewChunkedWriter(c)
			cw.Write([]byte(newBody))
			cw.Close()
			fmt.Fprint(c, "\r\n")
		case strings.Contains(reqLine, "/rewrite") && method == "RESPMOD":
			newHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Scanned: yes\r\n\r\n"
			fmt.Fprintf(c, "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s", len(newHdr), newHdr)
			cw := httputil.NewChunkedWriter(c)
			cw.Write([]byte("rewritten"))
			cw.Close()
			fmt.Fprint(c, "\r\n")
		case strings.Contains(reqLine, "/error"):
			fmt.Fprintf(c, "ICAP/1.0 500 Server Error\r\nEncapsulated: null-body=0\r\n\r\n")
			return
		case strings.Contains(reqLine, "/hang"):
			select {}
		default:
			fmt.Fprintf(c, "ICAP/1.0 204 No Content\r\nISTag: \"tag-1\"\r\n\r\n")
		}
		if f.CloseAfter {
			return
		}
	}
}

func (f *Server) block(c net.Conn) {
	page := "<html>blocked by scanner</html>"
	resHdr := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nX-Virus: found\r\n\r\n")
	fmt.Fprintf(c, "ICAP/1.0 200 OK\r\nISTag: \"tag-1\"\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s", len(resHdr), resHdr)
	cw := httputil.NewChunkedWriter(c)
	cw.Write([]byte(page))
	cw.Close()
	fmt.Fprint(c, "\r\n")
}
