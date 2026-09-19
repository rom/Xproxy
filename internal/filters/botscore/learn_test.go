package botscore

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func TestBaselinePercentile(t *testing.T) {
	var b baseline
	for i := 0; i < 90; i++ {
		b.add(5) // 90 samples at score 5
	}
	for i := 0; i < 10; i++ {
		b.add(95) // 10 at 95
	}
	// p50 sits in the low bucket (upper bound 10), p95/p99 in the high one.
	if got := b.percentile(0.50); got != 10 {
		t.Fatalf("p50 %d", got)
	}
	if got := b.percentile(0.95); got != 100 {
		t.Fatalf("p95 %d", got)
	}
	// A tenth of traffic scores at or above 90.
	if got := b.shareAtLeast(90); got < 0.09 || got > 0.11 {
		t.Fatalf("share >=90 = %v", got)
	}
	if b.shareAtLeast(0) != 0 {
		t.Fatal("share for a disabled threshold must be 0")
	}
}

func TestSuggestThresholds(t *testing.T) {
	// Low bulk, high tail: deny near the tail, challenge below it.
	deny, chal := suggestThresholds(10, 30)
	if deny != 30 || chal != 10 {
		t.Fatalf("deny %d challenge %d", deny, chal)
	}
	// Challenge must stay below deny even when the percentiles collide.
	deny, chal = suggestThresholds(60, 60)
	if chal >= deny {
		t.Fatalf("challenge %d not below deny %d", chal, deny)
	}
}

func TestLearnStatus(t *testing.T) {
	f, err := filtertest.Build("bot_score", "learner", filter.Options{
		"learn": true, "deny_at": 80, "challenge_at": 50, "log_at": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A browser-like request scores low; a curl request scores higher.
	browser := func() *http.Request {
		r := httptest.NewRequest("GET", "http://shop.test/", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11) Chrome/120")
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Accept-Language", "en")
		return r
	}
	bot := func() *http.Request {
		r := httptest.NewRequest("GET", "http://shop.test/", nil)
		r.Header.Set("User-Agent", "curl/8.0")
		return r
	}
	for i := 0; i < 40; i++ {
		filtertest.Run(f, browser(), nil)
	}
	for i := 0; i < 10; i++ {
		filtertest.Run(f, bot(), nil)
	}

	var eb *EndpointBaseline
	for _, fb := range Status(0).Filters {
		if fb.Filter != "learner" {
			continue
		}
		if fb.DenyAt != 80 || fb.ChallengeAt != 50 {
			t.Fatalf("thresholds %+v", fb)
		}
		for i := range fb.Endpoints {
			if fb.Endpoints[i].Route == "test" {
				eb = &fb.Endpoints[i]
			}
		}
	}
	if eb == nil {
		t.Fatal("no baseline recorded for the route")
	}
	if eb.Samples != 50 {
		t.Fatalf("samples %d", eb.Samples)
	}
	if eb.SuggestDenyAt < eb.SuggestChallengeAt || eb.SuggestDenyAt > 100 || eb.SuggestChallengeAt < 10 {
		t.Fatalf("suggestions out of range: %+v", eb)
	}
	// Clean up the global registry so other tests are unaffected.
	_ = f.(interface{ Close() error }).Close()
}
