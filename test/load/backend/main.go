// Command backend is a minimal upstream for load tests: it answers every
// request with a small body and echoes the Host header, so the proxy, not
// the backend, is what the load test measures. It binds the wildcard
// address so that endpoints on any loopback address (127.x.y.z) reach it.
//
//	go run ./test/load/backend -listen 0.0.0.0:9001 -size 1024
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:9001", "listen address")
	size := flag.Int("size", 1024, "response body size in bytes")
	delay := flag.Duration("delay", 0, "artificial response delay")
	flag.Parse()
	body := []byte(strings.Repeat("x", *size))
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if *delay > 0 {
				time.Sleep(*delay)
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("X-Backend-Host", r.Host)
			if r.URL.Path == "/healthz" {
				w.WriteHeader(200)
				return
			}
			_, _ = w.Write(body)
		}),
	}
	log.Printf("load backend on %s, %d byte body", ln.Addr(), *size)
	log.Fatal(srv.Serve(ln))
}
