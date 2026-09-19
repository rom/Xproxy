package bound

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNoticeThrottles(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	now := time.Unix(1_700_000_000, 0)
	n := &Notice{Interval: time.Minute, now: func() time.Time { return now }}
	for i := 0; i < 5; i++ {
		n.Hit(log, "table full", "table", "marks")
	}
	if n.Total() != 5 {
		t.Fatalf("total %d", n.Total())
	}
	if c := strings.Count(buf.String(), "table full"); c != 1 {
		t.Fatalf("%d warnings within the interval:\n%s", c, buf.String())
	}
	if !strings.Contains(buf.String(), "occurrences=1") || !strings.Contains(buf.String(), "table=marks") {
		t.Fatalf("first warning: %s", buf.String())
	}
	now = now.Add(2 * time.Minute)
	n.Hit(log, "table full")
	if c := strings.Count(buf.String(), "table full"); c != 2 || !strings.Contains(buf.String(), "occurrences=5") || !strings.Contains(buf.String(), "total=6") {
		t.Fatalf("second warning carries the count of the quiet period:\n%s", buf.String())
	}
}

func TestNoticeDefaults(t *testing.T) {
	var n Notice
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				n.Hit(nil, "concurrent")
			}
		}()
	}
	wg.Wait()
	if n.Total() != 800 {
		t.Fatalf("total %d", n.Total())
	}
}
