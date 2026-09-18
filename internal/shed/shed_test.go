package shed

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func cfg() *config.Shedding {
	return &config.Shedding{TargetLatency: config.Duration(100 * time.Millisecond), Window: config.Duration(2 * time.Second),
		Low: 0.6, Normal: 0.8, High: 0.95, Hysteresis: 0.1, RetryAfter: config.Duration(2 * time.Second)}
}

func TestInflightLevel(t *testing.T) {
	inflight := int64(0)
	s := New(cfg(), func() int64 { return inflight }, 100)
	if ok, level := s.Admit(Low); !ok || level != 0 {
		t.Fatalf("idle: %v %v", ok, level)
	}
	inflight = 70
	if ok, _ := s.Admit(Low); ok {
		t.Fatal("low admitted at 0.7")
	}
	if ok, _ := s.Admit(Normal); !ok {
		t.Fatal("normal shed at 0.7")
	}
	inflight = 96
	for _, c := range []Class{Low, Normal, High} {
		if ok, _ := s.Admit(c); ok {
			t.Fatalf("%s admitted at 0.96", c)
		}
	}
	if ok, _ := s.Admit(Critical); !ok {
		t.Fatal("critical shed")
	}
	// Hysteresis: low stays shed until below 0.5.
	inflight = 55
	if ok, _ := s.Admit(Low); ok {
		t.Fatal("low admitted inside hysteresis band")
	}
	inflight = 45
	if ok, _ := s.Admit(Low); !ok {
		t.Fatal("low not readmitted")
	}
	snap := s.Snapshot()
	if snap.ShedLow != 3 || snap.ShedNormal != 1 || snap.ShedHigh != 1 || snap.Admitted != 4 {
		t.Fatalf("%+v", snap)
	}
}

func TestLatencyLevelAndDrain(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New(cfg(), func() int64 { return 0 }, 100)
	s.now = func() time.Time { return now }
	// 150ms average against a 100ms target: level 0.5.
	for i := 0; i < 10; i++ {
		s.Observe(150 * time.Millisecond)
	}
	if l := s.Level(); l < 0.49 || l > 0.51 {
		t.Fatalf("level %v", l)
	}
	if ok, _ := s.Admit(Low); !ok {
		t.Fatal("low shed at 0.5")
	}
	// 190ms average: level 0.9, low and normal shed, high admitted.
	now = now.Add(100 * time.Millisecond)
	for i := 0; i < 200; i++ {
		s.Observe(192 * time.Millisecond)
	}
	if ok, _ := s.Admit(Low); ok {
		t.Fatal("low admitted")
	}
	if ok, _ := s.Admit(Normal); ok {
		t.Fatal("normal admitted")
	}
	if ok, _ := s.Admit(High); !ok {
		t.Fatal("high shed")
	}
	// Window passes with no samples: the signal drains and classes return.
	now = now.Add(3 * time.Second)
	if s.Latency() != 0 {
		t.Fatalf("latency did not drain: %v", s.Latency())
	}
	if ok, _ := s.Admit(Low); !ok {
		t.Fatal("low not readmitted after drain")
	}
	if s.RetryAfter() != 2*time.Second {
		t.Fatal("retry after")
	}
}

func TestReconfigureKeepsSamples(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New(cfg(), func() int64 { return 0 }, 100)
	s.now = func() time.Time { return now }
	s.Observe(300 * time.Millisecond)
	c := cfg()
	c.TargetLatency = config.Duration(400 * time.Millisecond)
	s.Reconfigure(c, 100)
	if s.Level() != 0 || s.Latency() != 300*time.Millisecond {
		t.Fatalf("level %v latency %v", s.Level(), s.Latency())
	}
	c.Window = config.Duration(4 * time.Second)
	s.Reconfigure(c, 100)
	if s.Latency() != 0 {
		t.Fatal("window change should reset samples")
	}
}
