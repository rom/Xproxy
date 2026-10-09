package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/intel"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/shadow"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// The views, against a management API that answers what a busy proxy would.
//
// Every one of these commands is somebody reading a column at three in the
// morning, and what makes them worth testing is not that they print
// something: it is that the number an operator acts on is the number the
// daemon reported. A proxy in a test reports almost nothing -- no circuit has
// tripped, no certificate is expiring, no client has been marked -- so the
// rendering is driven from canned answers instead, which is also the only way
// to put a value in a field and then look for it in the output.

// canned serves the given JSON bodies on a management socket of its own. The
// key is the path; a path the test does not name answers 404, which is what a
// view that asks for something optional has to cope with.
func canned(t *testing.T, bodies map[string]any) (sock, cfgPath string) {
	t.Helper()
	sock, cfgPath, _ = cannedWith(t, bodies)
	return sock, cfgPath
}

// sentBodies is what the command sent, by path, for the commands whose own
// arguments have to reach the daemon rather than only be parsed.
type sentBodies struct {
	mu   sync.Mutex
	last map[string]string
}

func (s *sentBodies) get(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last[path]
}

// cannedWith is canned with a record of what was sent to each path.
func cannedWith(t *testing.T, bodies map[string]any) (sock, cfgPath string, sent *sentBodies) {
	t.Helper()
	sent = &sentBodies{last: map[string]string{}}
	dir := t.TempDir()
	sock = filepath.Join(dir, "m.sock")
	cfgPath = filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(testYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	for path, body := range bodies {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		status := http.StatusOK
		if r, ok := body.(statusAnd); ok {
			status = r.code
			if raw, err = json.Marshal(r.body); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			sent.mu.Lock()
			sent.last[r.URL.Path] = r.Method + " " + r.URL.RawQuery + " " + string(body)
			sent.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(raw)
		})
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, cfgPath, sent
}

// statusAnd is a body served with a status code of its own, for the one
// endpoint whose non-2xx answer is an answer rather than a failure.
type statusAnd struct {
	code int
	body any
}

// The status page's optional sections: the authorisation policy and the
// imported lists. Both are absent on a proxy that has neither, so both are
// printed only when there is something to print -- and the numbers an
// operator reads from them are the ones that decide whether a policy is safe
// to enforce.
func TestTheStatusPageCarriesTheAuthorisationAndListSummaries(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/status": mgmt.Status{
			Version: "test", PID: 4242, Generation: 7,
			Listeners: map[string]string{"edge": "127.0.0.1:8443"},
			Routes:    3, Upstreams: 2,
			Stats: proxy.Snapshot{
				UptimeSeconds: 90,
				Authz: &proxy.AuthzSummary{
					DefaultAllows: false, Shadow: true,
					Allowed: 10, Denied: 3, NoRule: 1,
					Rules: []authorization.Status{
						{Name: "operators", Allow: true, Hits: 12},
						{Name: "everyone-else", Allow: false},
					},
				},
				ThreatLists: []intel.ListStatus{
					{Name: "feodo", Kind: "cidr", Action: "block", Entries: 1200, Hits: 4,
						Read: time.Now().Add(-time.Hour), Source: "https://feeds.invalid/feodo.txt"},
				},
			},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "status")
	if code != 0 {
		t.Fatalf("status: %d %s", code, errOut)
	}
	for _, want := range []string{
		"pid 4242", "generation 7", "authorization", "threat_list", "feodo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the status page lacks %q:\n%s", want, out)
		}
	}
	// Shadow mode is the fact that decides whether the policy is enforcing,
	// and an operator reading this page must not have to infer it.
	if !strings.Contains(out, "shadow") {
		t.Errorf("the summary does not say the policy is in shadow mode:\n%s", out)
	}
	// A rule that has decided nothing is either about traffic that does not
	// happen or shadowed by a rule above it, and both are worth seeing.
	for _, want := range []string{"operators", "hits=12", "everyone-else", "(never matched)", "1200"} {
		if !strings.Contains(out, want) {
			t.Errorf("the page lacks the reported figure %q:\n%s", want, out)
		}
	}
}

// The upstreams table, and the per-pool state under it. A circuit that is
// open and a queue that is full are the two reasons requests are being
// refused by this proxy rather than by anything behind it, so both are on the
// page with the endpoint table rather than somewhere else.
func TestTheUpstreamsTableCarriesTheCircuitAndTheQueue(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/upstreams": map[string][]upstream.Stats{
			"app": {
				{Address: "10.0.0.1:443", Weight: 5, Healthy: true, Active: 2, Requests: 100, Errors: 1, LatencyMS: 12.5, MaxActive: 64},
				{Address: "10.0.0.2:443", Weight: 1, Healthy: false, Ejected: true, Discovered: true, Ramp: 0.5},
			},
		},
		"/v1/pools": map[string]upstream.PoolStatus{
			"app": {
				Name: "app", Balancer: "ewma", Endpoints: 2, Available: 1, SlowStart: "30s",
				Discovery: &upstream.DiscoveryStatus{
					Type: "dns", Name: "app.svc.invalid", Interval: "30s", Endpoints: 2,
					Resolutions: 9, Changes: 2, Errors: 1, LastError: "no such host",
				},
				Circuit: &upstream.CircuitStatus{State: upstream.CircuitOpen, Failures: 5, Threshold: 5,
					Opens: 2, Rejected: 17, Until: time.Now().Add(30 * time.Second)},
				Queue: &upstream.QueueStatus{MaxConcurrent: 10, InFlight: 10, QueueSize: 20,
					Waiting: 4, Queued: 40, Timeouts: 3, Full: 1},
			},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "upstreams")
	if code != 0 {
		t.Fatalf("upstreams: %d %s", code, errOut)
	}
	for _, want := range []string{
		"10.0.0.1:443", "10.0.0.2:443",
		"64",  // the per-endpoint active bound, where one is set
		"dns", // a discovered endpoint is not a configured one
		"discovery dns app.svc.invalid", "last error: no such host",
		"slow start 30s",
		"CIRCUIT", "open until", "5/5", "17",
		"10/10", "4/20",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the upstreams page lacks %q:\n%s", want, out)
		}
	}
	// A dash where there is no bound, rather than a zero that reads as one.
	if !strings.Contains(out, "\t-\t") && !strings.Contains(out, " -  ") && !strings.Contains(out, " - ") {
		t.Errorf("an endpoint with no active bound did not print a dash:\n%s", out)
	}
}

// The readiness command is the one a load balancer check script runs, so the
// exit code is the answer and the three answers have to be distinguishable:
// carry traffic, do not, and the question could not be asked.
func TestReadinessAnswersWithItsExitCode(t *testing.T) {
	t.Run("serving", func(t *testing.T) {
		sock, cfgPath := canned(t, map[string]any{
			"/v1/ready": proxy.Readiness{Serving: true, Listeners: 2},
		})
		if code, out, _ := runCmd(t, sock, cfgPath, "ready"); code != 0 || !strings.Contains(out, "ready: 2 listener(s)") {
			t.Errorf("ready: %d %q", code, out)
		}
	})

	t.Run("not serving", func(t *testing.T) {
		sock, cfgPath := canned(t, map[string]any{
			"/v1/ready": statusAnd{code: http.StatusServiceUnavailable,
				body: proxy.Readiness{Serving: false, Reasons: []string{"no healthy endpoint"},
					PoolsWithoutEndpoints: []string{"app"}}},
		})
		code, out, _ := runCmd(t, sock, cfgPath, "ready")
		if code != 1 {
			t.Errorf("a node that should not carry traffic answered %d", code)
		}
		if !strings.Contains(out, "no healthy endpoint") {
			t.Errorf("the answer does not say why: %q", out)
		}
	})

	t.Run("stepping down and up", func(t *testing.T) {
		sock, cfgPath := canned(t, map[string]any{
			"/v1/ready": proxy.Readiness{Serving: false, SteppedDown: true,
				StepReason: "maintenance window", StepAt: time.Now(),
				Reasons: []string{"an operator stepped this node down: maintenance window"}},
		})
		code, out, _ := runCmd(t, sock, cfgPath, "ready", "-step-down", "maintenance window")
		if code != 0 {
			t.Errorf("step-down answered %d", code)
		}
		if !strings.Contains(out, "maintenance window") {
			t.Errorf("the answer does not carry the reason: %q", out)
		}
		// In JSON, because a script that steps a node down wants the state
		// back rather than a sentence.
		if code, out, _ := runCmd(t, sock, cfgPath, "-json", "ready", "-step-up"); code != 0 ||
			!strings.Contains(out, `"stepped_down"`) {
			t.Errorf("-json step-up: %d %q", code, out)
		}
		// The two are opposites, and asking for both is a mistake worth an
		// exit code rather than a guess at which was meant.
		if code, _, errOut := runCmd(t, sock, cfgPath, "ready", "-step-down", "x", "-step-up"); code != 2 ||
			!strings.Contains(errOut, "opposites") {
			t.Errorf("both at once: %d %q", code, errOut)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		// Not an answer at all: a check script that read this as "not ready"
		// would move an address because a socket permission changed.
		dir := t.TempDir()
		code, _, errOut := runCmd(t, filepath.Join(dir, "absent.sock"), filepath.Join(dir, "none.yaml"), "ready")
		if code != 2 {
			t.Errorf("an unreachable daemon answered %d", code)
		}
		if errOut == "" {
			t.Error("nothing was said about why the question could not be asked")
		}
	})
}

// The capture view and its two switches. A recording is a file of other
// people's traffic, so the view says whether one is running, where it is
// going and for how long -- every one of those being something an operator
// has to be able to see without reading the configuration.
func TestTheCaptureViewSaysWhatIsBeingRecorded(t *testing.T) {
	st := capture.Stats{
		Enabled: true, Active: true, Until: time.Now().Add(5 * time.Minute),
		File: "/var/log/xproxy/capture.pcapng", Files: 2,
		Captured: 12, Skipped: 3, Truncated: 1, DroppedFull: 4, WriteFailures: 1, Bytes: 4096,
		Rules: []capture.RuleStat{{Name: "ssh", Captured: 7, Limit: 10}, {Name: "all", Captured: 5}},
	}
	sock, cfgPath, sent := cannedWith(t, map[string]any{"/v1/capture": st})
	for _, args := range [][]string{{"capture"}, {"capture", "status"}, {"capture", "start", "-duration", "5m"}, {"capture", "stop"}} {
		code, out, errOut := runCmd(t, sock, cfgPath, args...)
		if code != 0 {
			t.Fatalf("%v: %d %s", args, code, errOut)
		}
		for _, want := range []string{"capture: on", "capture.pcapng (2 open)", "captured: 12", "rule ssh: 7/10", "rule all: 5"} {
			if !strings.Contains(out, want) {
				t.Errorf("%v lacks %q:\n%s", args, want, out)
			}
		}
	}
	// The duration reached the daemon. The usage puts the flag after the
	// subcommand, where the flag package stops parsing, so this is the case
	// that silently recorded for the configured maximum instead.
	if got := sent.get("/v1/capture"); !strings.Contains(got, `"duration":"5m0s"`) && !strings.Contains(got, `"active":false`) {
		t.Errorf("the capture request was %q", got)
	}
	if code, _, errOut := runCmd(t, sock, cfgPath, "capture", "start", "-duration", "5m"); code != 0 {
		t.Fatalf("capture start: %d %s", code, errOut)
	}
	if got := sent.get("/v1/capture"); !strings.Contains(got, `"duration":"5m0s"`) {
		t.Errorf("the duration did not reach the daemon: %q", got)
	}

	// A duration that cannot mean anything is refused rather than sent.
	if code, _, errOut := runCmd(t, sock, cfgPath, "capture", "start", "-duration", "-1s"); code != 2 ||
		!strings.Contains(errOut, "negative") {
		t.Errorf("a negative duration: %d %q", code, errOut)
	}
	if code, _, errOut := runCmd(t, sock, cfgPath, "capture", "sideways"); code != 2 ||
		!strings.Contains(errOut, "usage") {
		t.Errorf("an unknown subcommand: %d %q", code, errOut)
	}
	// And a proxy with no capture section says so rather than printing a
	// table of zeroes that reads as a recording nobody started.
	off, offCfg := canned(t, map[string]any{"/v1/capture": capture.Stats{}})
	if code, out, _ := runCmd(t, off, offCfg, "capture"); code != 0 ||
		!strings.Contains(out, "no capture section") {
		t.Errorf("a proxy with no capture section: %d %q", code, out)
	}
}

// The shadow report, which is the page an operator reads before turning a
// policy on. Its whole value is the EXAMPLE column: a count says how often a
// rule would have fired, and the example says what it would have fired on.
func TestTheShadowReportNamesWhatWouldHaveBeenRefused(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/policy": mgmt.PolicyReport{
			Status: shadow.Status{Entries: 2, Recorded: 9, Dropped: 3, Full: true},
			Entries: []shadow.Entry{
				{Kind: "smtp", Listener: "mail", Reason: "command_refused", Rule: "verbs", Count: 7,
					First: "10:00:00", Last: "10:05:00", Sample: "VRFY"},
				{Kind: "tcp", Listener: "l4", Reason: "no_route", Count: 2,
					First: "10:01:00", Last: "10:02:00", Sample: "stranger.test"},
			},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "policy")
	if code != 0 {
		t.Fatalf("policy: %d %s", code, errOut)
	}
	for _, want := range []string{
		"2 kinds of refusal recorded, 9 in total",
		"the ledger is full", "3 dropped",
		"command_refused", "VRFY", "stranger.test",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	// -top is for a report with thousands of rows, and it has to cut rather
	// than summarise: the rows it keeps are the ones the daemon ranked.
	if code, out, _ := runCmd(t, sock, cfgPath, "policy", "-top", "1"); code != 0 ||
		strings.Contains(out, "stranger.test") || !strings.Contains(out, "VRFY") {
		t.Errorf("policy -top 1: %d\n%s", code, out)
	}
	if code, _, errOut := runCmd(t, sock, cfgPath, "policy", "sideways"); code != 2 ||
		!strings.Contains(errOut, "report or reset") {
		t.Errorf("an unknown subcommand: %d %q", code, errOut)
	}
	// An empty report says which of the two reasons it is empty for.
	empty, emptyCfg := canned(t, map[string]any{"/v1/policy": mgmt.PolicyReport{}})
	if code, out, _ := runCmd(t, empty, emptyCfg, "policy"); code != 0 ||
		!strings.Contains(out, "nothing would have been refused") {
		t.Errorf("an empty report: %d %q", code, out)
	}
}

// The live sessions view and the kill it is read before using: a session is
// somebody's connection, so what the table says has to be enough to decide
// whether to end it.
func TestTheSessionsViewAndTheKill(t *testing.T) {
	live := []sessions.View{
		{ID: "s1", Kind: "ssh", Listener: "bastion", Client: "10.0.0.5:51000",
			Target: "10.1.0.9:22", User: "alice", Started: "10:00:00", DurationMS: 65000},
		{ID: "s2", Kind: "rdp", Listener: "desks", Client: "10.0.0.6:51001", Started: "10:02:00", DurationMS: 2000},
	}
	sock, cfgPath := canned(t, map[string]any{"/v1/sessions": live})
	code, out, errOut := runCmd(t, sock, cfgPath, "sessions")
	if code != 0 {
		t.Fatalf("sessions: %d %s", code, errOut)
	}
	for _, want := range []string{"s1", "ssh", "bastion", "alice", "10.1.0.9:22", "s2", "rdp"} {
		if !strings.Contains(out, want) {
			t.Errorf("the sessions table lacks %q:\n%s", want, out)
		}
	}
	// A proxy carrying nothing says so rather than printing a bare heading.
	none, noneCfg := canned(t, map[string]any{"/v1/sessions": []sessions.View{}})
	code, out, _ = runCmd(t, none, noneCfg, "sessions")
	if code != 0 || !strings.Contains(out, "ID") {
		t.Errorf("an idle proxy: %d %q", code, out)
	}
	for _, gone := range []string{"s1", "alice"} {
		if strings.Contains(out, gone) {
			t.Errorf("the empty table still names %q: %q", gone, out)
		}
	}
}

// Draining is the operator decision this process holds rather than a
// configuration: the view has to say which pools and endpoints are out of
// rotation, because nothing in the file says so.
func TestTheDrainViewListsTheDecisionsTheProcessHolds(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/drain": upstream.Decisions{
			Pools:     map[string]bool{"app": true},
			Endpoints: map[string]map[string]bool{"api": {"10.0.0.3:443": true}},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "drain")
	if code != 0 {
		t.Fatalf("drain: %d %s", code, errOut)
	}
	for _, want := range []string{"app", "api", "10.0.0.3:443"} {
		if !strings.Contains(out, want) {
			t.Errorf("the drain view lacks %q:\n%s", want, out)
		}
	}
}

// The TLS page gathers what a client meets before it has sent a request: the
// handshake policy, the certificates that are running out, and the key
// agreement groups with the share that actually used a post-quantum one.
func TestTheTLSPageGathersWhatAClientMeetsFirst(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/tls": map[string]any{},
		"/v1/handshake": proxy.HandshakeStatus{
			Enabled: true, RefuseBanned: true, Fingerprints: 12, Refused: 3,
		},
		"/v1/tls/expiring": map[string][]string{
			"edge": {"certificate edge.test expires on 2026-04-01T00:00:00Z, in 36h"},
		},
		"/v1/tls/key-exchange": proxy.KeyExchangeStatus{
			Groups:      map[string][]string{"edge": {"X25519MLKEM768", "X25519"}},
			Negotiated:  map[string]uint64{"X25519MLKEM768": 30, "X25519": 70},
			PostQuantum: 30,
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "tls")
	if code != 0 {
		t.Fatalf("tls: %d %s", code, errOut)
	}
	for _, want := range []string{
		"handshake: refuse_banned=true", "fingerprints=12", "refused=3",
		"EXPIRY edge:", "expires on",
		"key exchange edge: X25519MLKEM768, X25519",
		"X25519MLKEM768",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the tls page lacks %q:\n%s", want, out)
		}
	}
}

// The ticket keys are shared state: every node of a cluster has to hold the
// same set, so the view names the set and says which peers agree. A peer that
// does not is the one fact on the page worth acting on.
func TestTheTicketViewNamesTheSetAndWhoDisagrees(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/tls/tickets": tlsconf.TicketStatus{
			Enabled: true, Rotate: "24h0m0s", Epoch: 20321,
			EpochStarted: time.Now().Add(-time.Hour), NextRotation: time.Now().Add(23 * time.Hour),
			Keys: 4, MasterKeys: 2, Fingerprint: "ab12cd34", Rotations: 9,
			Peers: map[string]string{"node-b": "ab12cd34", "node-c": "ffffffff"},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "tls", "tickets")
	if code != 0 {
		t.Fatalf("tls tickets: %d %s", code, errOut)
	}
	for _, want := range []string{
		"epoch 20321", "keys 4 from 2 master key(s)", "fingerprint ab12cd34", "rotations 9",
		"peer node-b agrees", "peer node-c MISMATCH",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the ticket view lacks %q:\n%s", want, out)
		}
	}
}

// The honeypot page, which is three tables: the fabricated devices and who
// has been reading them, the planted credentials and whether any has been
// used, and the clients a honeypot route has marked. TRIPPED and HITS are
// the columns that are findings rather than statistics -- nothing legitimate
// touches a tripwire address or presents a planted credential.
func TestTheHoneypotPageNamesTheVisitorsAndTheFindings(t *testing.T) {
	now := time.Now()
	sock, cfgPath, sent := cannedWith(t, map[string]any{
		"/v1/honeypot": map[string]any{
			"decoys": []string{"env", "wp-config"},
			"device_decoys": []proxy.DecoyStatus{
				{Listener: "plant", Kind: "modbus", Mode: "decoy", Profile: "plc", Served: 40, Tripped: 2,
					Anyone: true, Visitors: []proxy.DecoyVisitor{
						{ClientIP: "10.0.0.9", FirstSeen: "10:00:00", LastSeen: "10:30:00", Frames: 40, Tripped: 2},
					}},
				{Listener: "sql", Kind: "mysql", Mode: "answer", Profile: "generic-mysql", Served: 3},
			},
			"honeytokens": []proxy.HoneytokenStatus{
				{Name: "aws-root", Description: "planted in /backup.sql", Action: "ban", Match: "header",
					Values: 2, Fields: []string{"authorization", "x-api-key"}, Hits: 1, LastHit: now},
				{Name: "db-password", Action: "log", Match: "body", Values: 1, Fields: []string{"password"}},
			},
			"marks": []proxy.Mark{
				{Address: "203.0.113.9", Route: "trap", Hits: 4, First: now.Add(-time.Hour), Last: now, Expires: now.Add(time.Hour)},
			},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "honeypot")
	if code != 0 {
		t.Fatalf("honeypot: %d %s", code, errOut)
	}
	for _, want := range []string{
		"decoys: env, wp-config",
		"LISTENER", "plant", "modbus", "anybody", // a decoy that lies to everyone
		"sql", "listed", // and one that lies only to the named clients
		"VISITOR", "10.0.0.9",
		"TOKEN", "aws-root", "authorization,x-api-key", "planted in /backup.sql",
		"db-password",
		"ADDRESS", "203.0.113.9", "trap",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the honeypot page lacks %q:\n%s", want, out)
		}
	}
	// A token that has never been presented shows a dash rather than the
	// zero time, which would read as 1 January year one.
	if strings.Contains(out, "0001-01-01") {
		t.Errorf("a zero time reached the page:\n%s", out)
	}

	// Forgetting a mark is the one mutating call on this page, and what it
	// answers is whether there was anything to forget.
	forget, forgetCfg, forgetSent := cannedWith(t, map[string]any{
		"/v1/honeypot": map[string]any{"removed": true},
	})
	code, out, errOut = runCmd(t, forget, forgetCfg, "honeypot", "forget", "203.0.113.9")
	if code != 0 {
		t.Fatalf("honeypot forget: %d %s", code, errOut)
	}
	if !strings.Contains(out, "removed: true") {
		t.Errorf("forget answered %q", out)
	}
	if got := forgetSent.get("/v1/honeypot"); !strings.Contains(got, "DELETE") ||
		!strings.Contains(got, "203.0.113.9") {
		t.Errorf("the address did not reach the daemon: %q", got)
	}
	_ = sent
}

// The quota page: what each tenant and each rate limit policy has done.
// TOP is the column it exists for -- a limit that is denying has a consumer
// behind it, and an operator needs the key rather than the count.
func TestTheQuotaPageNamesTheTenantsAndTheHeaviestConsumers(t *testing.T) {
	sock, cfgPath, sent := cannedWith(t, map[string]any{
		"/v1/quotas": proxy.QuotaReport{
			Generated: time.Now(), Generation: 4,
			Tenants: []proxy.TenantQuota{
				{Tenant: "acme", Routes: 2, Requests: 900, Denied: 4, RateLimited: 7, BytesIn: 1024, BytesOut: 4096},
			},
			Routes: []proxy.RouteQuota{
				{Route: "app", Tenant: "acme", Upstream: "app", Requests: 900, Status2xx: 880, Status4xx: 20,
					LatencyP50MS: 3, LatencyP95MS: 40, LatencyP99MS: 90},
			},
			RateLimits: []proxy.PolicyQuota{
				{Policy: "per-ip", Key: "ip", Algorithm: "token_bucket", Distributed: "local",
					Rate: 10, Burst: 20, Keys: 3, Allowed: 500, Denied: 9,
					Top: []limits.KeyUsage{{Key: "203.0.113.9", Total: 120, Tokens: 0.5}}},
				{Policy: "per-token", Key: "jwt:sub", Algorithm: "sliding_window", Distributed: "exact",
					Limit: 100, Window: "1m", Keys: 2, Allowed: 80, Denied: 1},
			},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "quotas", "-top", "3")
	if code != 0 {
		t.Fatalf("quotas: %d %s", code, errOut)
	}
	for _, want := range []string{
		"TENANT", "acme", "900",
		"ROUTE", "app",
		"POLICY", "per-ip", "token_bucket", "10/s burst 20", "203.0.113.9=120/0.5",
		"per-token", "100 per 1m", // a sliding window is a count per window, not a rate
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the quota page lacks %q:\n%s", want, out)
		}
	}
	// -top is the daemon's work, not the command's: it asks for that many.
	if got := sent.get("/v1/quotas"); !strings.Contains(got, "top=3") {
		t.Errorf("the request was %q", got)
	}
}

// The API inventory, where the point is the state column: a shadow endpoint
// is one serving traffic that no description mentions, and a zombie is one
// that has stopped. Both are findings about an estate nobody has an
// up-to-date drawing of.
func TestTheAPIInventoryNamesTheShadowAndZombieEndpoints(t *testing.T) {
	now := time.Now()
	sock, cfgPath, sent := cannedWith(t, map[string]any{
		"/v1/api": apiinv.Report{
			Enabled: true, Since: now.Add(-48 * time.Hour), Endpoints: 3, MaxEndpoints: 1000,
			Dropped: 2, Shadow: 1, Zombie: 1, Superseded: 1, ZombieAfter: "168h0m0s", View: "all",
			Items: []apiinv.Endpoint{
				{Host: "api.test", Method: "GET", Path: "/v2/orders", Route: "api", Version: "v2",
					Requests: 500, Status2xx: 490, Status4xx: 10, Auth: []string{"jwt"},
					LastSeen: now, Documented: "yes"},
				{Host: "api.test", Method: "POST", Path: "/internal/debug", Route: "api",
					Requests: 3, Shadow: true, LastSeen: now},
				{Host: "api.test", Method: "GET", Path: "/v1/orders", Route: "api", Version: "v1",
					Requests: 0, Zombie: true, Superseded: true, LastSeen: now.Add(-300 * time.Hour)},
			},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "api")
	if code != 0 {
		t.Fatalf("api: %d %s", code, errOut)
	}
	for _, want := range []string{
		"endpoints 3/1000", "dropped 2", "shadow 1", "zombie 1", "superseded 1",
		"/v2/orders", "documented", "/internal/debug", "shadow", "/v1/orders", "zombie",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the inventory lacks %q:\n%s", want, out)
		}
	}
	// A view is sent to the daemon rather than filtered here, because the
	// inventory is the daemon's and -top has to mean the same thing.
	if code, _, _ := runCmd(t, sock, cfgPath, "api", "shadow", "-top", "5"); code != 0 {
		t.Errorf("api shadow: %d", code)
	}
	if got := sent.get("/v1/api"); !strings.Contains(got, "view=shadow") || !strings.Contains(got, "top=5") {
		t.Errorf("the request was %q", got)
	}
	if code, _, errOut := runCmd(t, sock, cfgPath, "api", "sideways"); code != 2 ||
		!strings.Contains(errOut, "usage: xproxyctl api") {
		t.Errorf("an unknown view: %d %q", code, errOut)
	}
	// An inventory that was never turned on says so rather than printing an
	// empty table that reads as an estate with no endpoints.
	off, offCfg := canned(t, map[string]any{"/v1/api": apiinv.Report{}})
	if code, out, _ := runCmd(t, off, offCfg, "api"); code != 0 || !strings.Contains(out, "not configured") {
		t.Errorf("an inventory that is off: %d %q", code, out)
	}
	// And one that is on with nothing in the view says which view.
	empty, emptyCfg := canned(t, map[string]any{"/v1/api": apiinv.Report{Enabled: true, MaxEndpoints: 10}})
	if code, out, _ := runCmd(t, empty, emptyCfg, "api", "zombie"); code != 0 ||
		!strings.Contains(out, "no endpoints in view zombie") {
		t.Errorf("an empty view: %d %q", code, out)
	}
}

// The origin lock's own check, which is the one command here whose exit code
// is a verdict about the estate rather than about the request: an origin that
// answers an unsigned probe is an origin anybody on the network can reach
// directly, and the lock is not protecting it.
func TestTheOriginCheckExitsNonZeroWhenTheLockIsNotProtecting(t *testing.T) {
	t.Run("enforced", func(t *testing.T) {
		sock, cfgPath, sent := cannedWith(t, map[string]any{
			"/v1/origin-check": []proxy.OriginCheckResult{
				{Upstream: "app", Endpoint: "10.0.0.1:443", UnsignedStatus: 403, SignedStatus: 200, Verdict: "enforced"},
			},
		})
		code, out, errOut := runCmd(t, sock, cfgPath, "origin-check", "app", "-host", "app.test", "-path", "/health")
		if code != 0 {
			t.Fatalf("origin-check: %d %s", code, errOut)
		}
		for _, want := range []string{"UPSTREAM", "10.0.0.1:443", "403", "200", "enforced"} {
			if !strings.Contains(out, want) {
				t.Errorf("the check lacks %q:\n%s", want, out)
			}
		}
		// What to probe is the operator's to say, and it has to reach the
		// daemon: the probe is made from there, not from here.
		got := sent.get("/v1/origin-check")
		for _, want := range []string{"upstream=app", "host=app.test", "path=%2Fhealth"} {
			if !strings.Contains(got, want) {
				t.Errorf("the request %q lacks %q", got, want)
			}
		}
	})

	t.Run("not enforced", func(t *testing.T) {
		sock, cfgPath := canned(t, map[string]any{
			"/v1/origin-check": []proxy.OriginCheckResult{
				{Upstream: "app", Endpoint: "10.0.0.1:443", UnsignedStatus: 200, SignedStatus: 200, Verdict: "not enforced"},
				{Upstream: "api", Endpoint: "10.0.0.2:443", UnsignedError: "connection refused", Verdict: "inconclusive"},
			},
		})
		code, out, _ := runCmd(t, sock, cfgPath, "origin-check")
		if code != 1 {
			t.Errorf("an origin anybody can reach answered %d", code)
		}
		for _, want := range []string{"not enforced", "inconclusive", "connection refused"} {
			if !strings.Contains(out, want) {
				t.Errorf("the check lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("nothing to check", func(t *testing.T) {
		sock, cfgPath := canned(t, map[string]any{"/v1/origin-check": []proxy.OriginCheckResult{}})
		if code, out, _ := runCmd(t, sock, cfgPath, "origin-check"); code != 0 ||
			!strings.Contains(out, "no upstream has an origin_signature") {
			t.Errorf("an estate with no signatures: %d %q", code, out)
		}
	})
}

// The technique view speaks the vocabulary an operations centre catalogues
// detections in. The catalogue and what has been seen are different
// questions: a zero against a technique says "nothing tried" only where the
// listener that could observe it exists.
func TestTheTechniqueViewAnswersBothQuestions(t *testing.T) {
	sock, cfgPath := canned(t, map[string]any{
		"/v1/status": mgmt.Status{
			Version: "test", Stats: proxy.Snapshot{Techniques: map[string]uint64{"T0842": 3}},
		},
	})
	code, out, errOut := runCmd(t, sock, cfgPath, "techniques")
	if code != 0 {
		t.Fatalf("techniques: %d %s", code, errOut)
	}
	for _, want := range []string{"TECHNIQUE", "T0842", "3"} {
		if !strings.Contains(out, want) {
			t.Errorf("the view lacks %q:\n%s", want, out)
		}
	}
	// The catalogue is longer than what has been seen, by definition.
	_, full, _ := runCmd(t, sock, cfgPath, "techniques", "-catalogue")
	if len(full) <= len(out) {
		t.Errorf("the catalogue is no longer than the seen list:\n%s", full)
	}
	// One matrix at a time, because the two are different estates: an ICS
	// technique on an office listener is a rule somebody wrote wrongly.
	if code, ics, _ := runCmd(t, sock, cfgPath, "techniques", "-catalogue", "-matrix", "ics"); code != 0 ||
		strings.Contains(ics, "enterprise") {
		t.Errorf("-matrix ics: %d\n%s", code, ics)
	}
	if code, _, errOut := runCmd(t, sock, cfgPath, "techniques", "-matrix", "sideways"); code != 2 ||
		!strings.Contains(errOut, "ics or enterprise") {
		t.Errorf("an unknown matrix: %d %q", code, errOut)
	}
	// And a daemon that has seen nothing says so, with what to ask instead.
	quiet, quietCfg := canned(t, map[string]any{"/v1/status": mgmt.Status{Version: "test"}})
	if code, out, _ := runCmd(t, quiet, quietCfg, "techniques"); code != 0 ||
		!strings.Contains(out, "-catalogue") {
		t.Errorf("a quiet daemon: %d %q", code, out)
	}
}
