package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEncoder(t *testing.T) {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	e.Counter("x_total", "Total x.", nil, 3)
	e.Gauge("y", "Gauge y with \"quotes\"\nand newline", Labels{"b": "2", "a": `q"u\o`}, 1.5)
	h := NewHistogram([]float64{0.1, 1})
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(5)
	e.Histogram("d_seconds", "Durations.", Labels{"k": "v"}, h.Snapshot())
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := []string{
		"# HELP x_total Total x.\n# TYPE x_total counter\nx_total 3\n",
		"# HELP y Gauge y with \"quotes\"\\nand newline\n# TYPE y gauge\n",
		`y{a="q\"u\\o",b="2"} 1.5` + "\n",
		"# TYPE d_seconds histogram\n",
		`d_seconds_bucket{k="v",le="0.1"} 1` + "\n",
		`d_seconds_bucket{k="v",le="1"} 2` + "\n",
		`d_seconds_bucket{k="v",le="+Inf"} 3` + "\n",
		`d_seconds_sum{k="v"} 5.55` + "\n",
		`d_seconds_count{k="v"} 3` + "\n",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("missing %q in:\n%s", w, out)
		}
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram(DurationBuckets)
	for _, v := range []float64{0.0005, 0.02, 0.3, 100} {
		h.Observe(v)
	}
	s := h.Snapshot()
	if s.Count != 4 || s.Sum != 100.3205 || s.Counts[0] != 1 || s.Counts[4] != 1 || s.Counts[8] != 1 {
		t.Fatalf("%+v", s)
	}
	var over uint64
	for _, c := range s.Counts {
		over += c
	}
	if over != 3 { // 100 exceeds every bound and only counts in +Inf
		t.Fatalf("bucketed %d", over)
	}
}

func TestSeriesAndSampler(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	src := func() Sample { return Sample{} }
	s := NewSampler([]string{"req"}, []string{"open"}, 10*time.Second, 40*time.Second, src)
	// 4 points fit; the fifth overwrites the first.
	prev := Sample{Counters: []float64{0}, Gauges: []float64{1}}
	for i := 1; i <= 5; i++ {
		cur := Sample{Counters: []float64{float64(i * 100)}, Gauges: []float64{float64(i)}}
		s.Tick(prev, cur, now.Add(time.Duration(i-1)*10*time.Second), now.Add(time.Duration(i)*10*time.Second))
		prev = cur
	}
	pts := s.Series().Since(time.Time{}, 0)
	if len(pts) != 4 || pts[0].Values[0] != 10 || pts[0].Values[1] != 2 || pts[3].Values[1] != 5 {
		t.Fatalf("points %+v", pts)
	}
	if !pts[0].Time.Before(pts[1].Time) {
		t.Fatal("order")
	}
	if got := s.Series().Since(now.Add(35*time.Second), 0); len(got) != 2 {
		t.Fatalf("since: %d", len(got))
	}
	if got := s.Series().Since(time.Time{}, 1); len(got) != 1 || got[0].Values[1] != 5 {
		t.Fatalf("limit: %+v", got)
	}
	// Counter reset yields zero, not a negative rate.
	s.Tick(Sample{Counters: []float64{500}, Gauges: []float64{0}}, Sample{Counters: []float64{5}, Gauges: []float64{0}}, now, now.Add(10*time.Second))
	last := s.Series().Since(time.Time{}, 1)
	if last[0].Values[0] != 0 {
		t.Fatal("reset handling")
	}
	if len(s.Series().Names()) != 2 || s.Series().Interval() != 10*time.Second {
		t.Fatal("names/interval")
	}
	// Start and stop the background loop.
	s.Start()
	s.Stop()
	s.Stop()
}
