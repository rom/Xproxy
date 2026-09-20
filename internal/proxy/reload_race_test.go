package proxy

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Several scalars were read on the request path and written by a
// reload: the cache's bounds, the shedder's bucket span and concurrency
// ceiling, the inventory's start time and logger, a QUIC flow's peeked
// server name. Each is word-sized, so nothing was observed to go wrong
// — and nothing would have been, because no test reloaded while
// requests were in flight. This one does, under -race.
func TestReloadUnderLoad(t *testing.T) {
	backend := newBackend(t, "a")
	yaml := func(maxObject string, window string) string {
		return fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
cache: {max_bytes: 1048576, max_object_bytes: %s}
shedding: {target_latency: 100ms, window: %s}
api_inventory: {enabled: true}
upstreams:
  - name: u
    endpoints: [{address: %q}]
routes:
  - name: r
    paths: [/]
    cache: {ttl: 1s}
    upstream: u
`, maxObject, window, backend.addr())
	}
	s, url := startServer(t, yaml("65536", "10s"))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := c.Get(fmt.Sprintf("%s/x?w=%d-%d", url, n, j%16))
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				// Read the views a management client would.
				_ = s.Stats()
				_ = s.APIInventory("all", 5)
			}
		}(i)
	}
	for i := 0; i < 12; i++ {
		maxObject, window := "65536", "10s"
		if i%2 == 1 {
			maxObject, window = "32768", "5s"
		}
		if err := s.Reload(mustParse(t, yaml(maxObject, window))); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("reload %d: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
