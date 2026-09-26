package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// pushService is an approval service: it records what it was asked and answers
// what the test told it to.
type pushService struct {
	mu       sync.Mutex
	requests []map[string]any
	// answer is the result for the POST; poll is what a later GET answers,
	// which is how a service that does not block is exercised.
	answer, poll string
	// status, when set, is answered instead of a body.
	status int
	// nonce, when set, is answered instead of the one that was asked about.
	nonce string
	// delay holds the answer, for the timeout case.
	delay time.Duration
	srv   *httptest.Server
}

func newPushService(t *testing.T, answer string) *pushService {
	t.Helper()
	s := &pushService{answer: answer}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		delay, status, nonce, answer, poll := s.delay, s.status, s.nonce, s.answer, s.poll
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			body["_auth"] = r.Header.Get("Authorization")
			s.requests = append(s.requests, body)
			if nonce == "" {
				nonce, _ = body["nonce"].(string)
			}
		} else if nonce == "" {
			nonce = r.URL.Query().Get("nonce")
			answer = poll
		}
		s.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pushAnswer{Nonce: nonce, Result: answer})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *pushService) seen() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.requests...)
}

func (s *pushService) set(fn func(*pushService)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// pusher builds a Pusher against a service, with the bounds a test wants.
func pusher(t *testing.T, cfg PushConfig) *Pusher {
	t.Helper()
	p, err := NewPusher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The answer decides, and every way of not getting one is a refusal.
func TestAPushIsApprovedOrItIsNot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*pushService)
		wantErr error
	}{
		{name: "approved", prepare: func(s *pushService) { s.answer = "approved" }},
		{name: "denied", prepare: func(s *pushService) { s.answer = "denied" }, wantErr: ErrPushDenied},
		// A service that answers "pending" is asked again, and the second
		// answer decides. No second notification is sent.
		{name: "pending then approved", prepare: func(s *pushService) { s.answer, s.poll = "pending", "approved" }},
		{name: "pending then denied", prepare: func(s *pushService) { s.answer, s.poll = "pending", "denied" }, wantErr: ErrPushDenied},
		// Nobody answers: the session is refused rather than held open, and
		// refused rather than let through.
		{name: "pending for ever", prepare: func(s *pushService) { s.answer, s.poll = "pending", "pending" }, wantErr: ErrPushTimeout},
		{name: "a refusal from the service", prepare: func(s *pushService) { s.status = http.StatusForbidden }, wantErr: ErrPushUnreachable},
		{name: "an answer this cannot read", prepare: func(s *pushService) { s.answer = "maybe" }, wantErr: ErrPushUnreachable},
		// An answer about another request is not an answer about this one: a
		// service that could hand over somebody else's approval could approve
		// a session nobody asked about.
		{name: "an answer about another request", prepare: func(s *pushService) { s.nonce = "0123456789abcdef" }, wantErr: ErrPushUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newPushService(t, "approved")
			svc.set(tc.prepare)
			p := pusher(t, PushConfig{URL: svc.srv.URL, Timeout: 300 * time.Millisecond, Poll: 20 * time.Millisecond})
			req, err := p.Begin("alice", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer p.Done(req)
			err = p.Wait(context.Background(), req, PushSubject{User: "alice", Listener: "bastion", Protocol: "ssh", ClientIP: "203.0.113.7"})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v, want %v", err, tc.wantErr)
			}
			// Whatever happened, exactly one notification was sent.
			if n := len(svc.seen()); n != 1 {
				t.Errorf("%d notifications sent, want 1", n)
			}
		})
	}
}

// What the service is told, which is what the person deciding has to see.
func TestTheRequestSaysWhoIsSigningInAndWhere(t *testing.T) {
	svc := newPushService(t, "approved")
	p := pusher(t, PushConfig{URL: svc.srv.URL, Token: "s3cret", Timeout: time.Second})
	req, err := p.Begin("alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Done(req)
	if req.Number == "" || len(req.Number) != 2 {
		t.Fatalf("number %q, want two digits", req.Number)
	}
	if !strings.Contains(req.Prompt(), req.Number) {
		t.Errorf("the prompt does not show the number: %q", req.Prompt())
	}
	if err := p.Wait(context.Background(), req, PushSubject{User: "alice", Listener: "bastion", Protocol: "ssh", ClientIP: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	seen := svc.seen()
	if len(seen) != 1 {
		t.Fatalf("%d requests", len(seen))
	}
	for k, want := range map[string]string{
		"user": "alice", "listener": "bastion", "protocol": "ssh",
		"client_ip": "203.0.113.7", "number": req.Number, "_auth": "Bearer s3cret",
	} {
		if got, _ := seen[0][k].(string); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if got, _ := seen[0]["nonce"].(string); len(got) != 32 {
		t.Errorf("nonce %q, want 128 bits of hex", got)
	}
	// Numbers can be turned off for a service that does not show them, and
	// then the prompt says what to do without one.
	off := false
	p2 := pusher(t, PushConfig{URL: svc.srv.URL, Numbers: &off, Timeout: time.Second})
	r2, err := p2.Begin("bob", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Done(r2)
	if r2.Number != "" {
		t.Errorf("number %q with numbers off", r2.Number)
	}
	if !strings.Contains(r2.Prompt(), "Approve") {
		t.Errorf("prompt %q", r2.Prompt())
	}
}

// The fatigue attack, refused twice over: one request at a time per user, and
// a bound per window. Neither refusal sends a notification, which is the whole
// point -- the attack is the notifications themselves.
func TestPushFatigueIsRefusedWithoutSendingAnything(t *testing.T) {
	svc := newPushService(t, "approved")
	p := pusher(t, PushConfig{URL: svc.srv.URL, Timeout: time.Second, PerWindow: 2, Window: time.Minute})
	now := time.Now()
	first, err := p.Begin("alice", now)
	if err != nil {
		t.Fatal(err)
	}
	// A second attempt while the first is waiting.
	if _, err := p.Begin("alice", now); !errors.Is(err, ErrPushPending) {
		t.Errorf("a second request while one waits: %v, want %v", err, ErrPushPending)
	}
	p.Done(first)
	// Now the window: two are allowed, the third is not.
	second, err := p.Begin("alice", now)
	if err != nil {
		t.Fatal(err)
	}
	p.Done(second)
	if _, err := p.Begin("alice", now); !errors.Is(err, ErrPushThrottled) {
		t.Errorf("the third request in the window: %v, want %v", err, ErrPushThrottled)
	}
	// Another user is unaffected: the bound is per user, so one person under
	// attack does not lock the estate out.
	other, err := p.Begin("bob", now)
	if err != nil {
		t.Errorf("another user was refused: %v", err)
	}
	p.Done(other)
	// And the window passes.
	later, err := p.Begin("alice", now.Add(2*time.Minute))
	if err != nil {
		t.Errorf("after the window: %v", err)
	}
	p.Done(later)
	if n := len(svc.seen()); n != 0 {
		t.Errorf("%d notifications sent by Begin alone; sending is Wait's job", n)
	}
	if got := p.Throttled.Load(); got != 2 {
		t.Errorf("throttled %d, want the two refusals", got)
	}
}

// A service that cannot be reached at all is a refusal, and the counters say
// which kind of failure it was.
func TestPushCountersSeparateADenialFromAnOutage(t *testing.T) {
	svc := newPushService(t, "denied")
	p := pusher(t, PushConfig{URL: svc.srv.URL, Timeout: 300 * time.Millisecond, Poll: 20 * time.Millisecond})
	run := func() error {
		req, err := p.Begin("alice", time.Now())
		if err != nil {
			return err
		}
		defer p.Done(req)
		return p.Wait(context.Background(), req, PushSubject{User: "alice"})
	}
	if err := run(); !errors.Is(err, ErrPushDenied) {
		t.Fatalf("denied: %v", err)
	}
	svc.set(func(s *pushService) { s.status = http.StatusInternalServerError })
	if err := run(); !errors.Is(err, ErrPushUnreachable) {
		t.Fatalf("unreachable: %v", err)
	}
	if p.Denied.Load() != 1 || p.Failed.Load() != 1 || p.Sent.Load() != 2 || p.Approved.Load() != 0 {
		t.Errorf("sent=%d approved=%d denied=%d failed=%d", p.Sent.Load(), p.Approved.Load(), p.Denied.Load(), p.Failed.Load())
	}
}

// The configuration a pusher refuses to be built from.
func TestAPushServiceIsCheckedWhenItIsBuilt(t *testing.T) {
	for _, tc := range []struct {
		cfg  PushConfig
		want string
	}{
		{PushConfig{}, "url is required"},
		{PushConfig{URL: "ftp://approve.example/"}, "http:// or https:// URL"},
		{PushConfig{URL: "https:///approve"}, "no host"},
		{PushConfig{URL: "https://approve.example/", Insecure: true}, "two decisions rather than one"},
		{PushConfig{URL: "https://approve.example/", Insecure: true, AllowInsecure: true}, "not a loopback address"},
	} {
		if _, err := NewPusher(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: error %v, want one about %q", tc.cfg, err, tc.want)
		}
	}
	// Verification may be skipped for a development instance on this machine.
	if _, err := NewPusher(PushConfig{URL: "https://127.0.0.1:8443/approve", Insecure: true, AllowInsecure: true}); err != nil {
		t.Errorf("a loopback development instance: %v", err)
	}
}

// A nil pusher answers rather than panicking: a listener with no push
// configured asks nothing, and a refusal is what a missing factor means.
func TestANilPusherRefuses(t *testing.T) {
	var p *Pusher
	if _, err := p.Begin("alice", time.Now()); !errors.Is(err, ErrPushUnreachable) {
		t.Errorf("Begin on a nil pusher: %v", err)
	}
	p.Done(nil)
	if err := p.Wait(context.Background(), nil, PushSubject{}); !errors.Is(err, ErrPushUnreachable) {
		t.Errorf("Wait on a nil pusher: %v", err)
	}
	var r *PushRequest
	if r.Prompt() != "" {
		t.Error("a nil request has a prompt")
	}
}
