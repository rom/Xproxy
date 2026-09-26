package ssh_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/mfa"
)

// approvals is an approval service: it answers what the test says and records
// what it was asked, so the assertions can be about the request as well as the
// decision.
type approvals struct {
	mu     sync.Mutex
	seen   []map[string]any
	result string
	status int
}

func newApprovals(t *testing.T, result string) (*approvals, string) {
	t.Helper()
	a := &approvals{result: result}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		result, status := a.result, a.status
		nonce := r.URL.Query().Get("nonce")
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			a.seen = append(a.seen, body)
			nonce, _ = body["nonce"].(string)
		}
		a.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"nonce":%q,"result":%q}`, nonce, result)
	}))
	t.Cleanup(srv.Close)
	return a, srv.URL
}

func (a *approvals) requests() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.seen...)
}

// The push factor end to end: the key is a partial success, the client is shown
// the number to compare, the service is asked, and the session exists only once
// it says yes.
func TestTheSecondFactorCanBeApprovedOnADevice(t *testing.T) {
	svc, url := newApprovals(t, "approved")
	s, addr, key, tg := bastion(t, "        mfa:\n          push: {url: "+url+", timeout: 10s, token: letmein}")
	var shown string
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "alice",
		Auth: []cssh.AuthMethod{
			cssh.PublicKeys(key),
			// A round with no questions is how the protocol shows a message:
			// the instruction carries the number and there is nothing to type.
			cssh.KeyboardInteractive(func(_, instruction string, qs []string, _ []bool) ([]string, error) {
				shown = instruction
				if len(qs) != 0 {
					t.Errorf("the push factor asked %d questions", len(qs))
				}
				return nil, nil
			}),
		},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with the push factor: %v", err)
	}
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("exec: %q %v", out, err)
	}
	if len(tg.seen()) == 0 {
		t.Fatal("nothing reached the target")
	}
	// The number the user is told to compare is the number the service was
	// sent: an approval nobody can match is an approval nobody can check.
	reqs := svc.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d approval requests", len(reqs))
	}
	number, _ := reqs[0]["number"].(string)
	if number == "" || !strings.Contains(shown, number) {
		t.Errorf("the client was shown %q and the service was sent %q", shown, number)
	}
	for k, want := range map[string]string{"user": "alice", "protocol": "ssh", "listener": "bastion"} {
		if got, _ := reqs[0][k].(string); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if sn := s.Stats(); sn.MFAPushApproved != 1 || sn.MFAPushSent != 1 || sn.MFAVerified != 1 {
		t.Errorf("sent=%d approved=%d verified=%d", sn.MFAPushSent, sn.MFAPushApproved, sn.MFAVerified)
	}
}

// Refused on the device, and refused by a service that cannot answer: the
// session does not exist either way, and the two are counted apart.
func TestAPushThatIsNotApprovedIsNotASession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result string
		status int
		denied uint64
		failed uint64
	}{
		{name: "the user says no", result: "denied", denied: 1},
		{name: "the service cannot answer", status: http.StatusBadGateway, failed: 1},
		{name: "the answer is not one this knows", result: "maybe", failed: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, url := newApprovals(t, tc.result)
			svc.mu.Lock()
			svc.status = tc.status
			svc.mu.Unlock()
			s, addr, key, _ := bastion(t, "        mfa:\n          push: {url: "+url+", timeout: 10s, token: letmein}")
			_, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
				User: "alice",
				Auth: []cssh.AuthMethod{
					cssh.PublicKeys(key),
					cssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) { return nil, nil }),
				},
				HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
				Timeout:         10 * time.Second,
			})
			if err == nil {
				t.Fatal("a session without an approval")
			}
			sn := s.Stats()
			if sn.MFAPushDenied != tc.denied || sn.MFAPushFailed != tc.failed {
				t.Errorf("denied=%d failed=%d, want %d and %d", sn.MFAPushDenied, sn.MFAPushFailed, tc.denied, tc.failed)
			}
			if sn.MFAVerified != 0 {
				t.Error("a refused approval counted as a verified factor")
			}
		})
	}
}

// With an enrolment file beside the approval service, an enrolled user types a
// code and everybody else is pushed. That is the shape an estate migrating
// between the two has, and it is the one thing about this that could silently
// give somebody the wrong factor.
func TestAnEnrolledUserTypesACodeAndTheRestArePushed(t *testing.T) {
	svc, url := newApprovals(t, "approved")
	dir := t.TempDir()
	mfaFile, secret := enrolMFA(t, dir, "bob") // alice is not enrolled
	_, addr, key, _ := bastion(t, "        mfa:\n          file: "+mfaFile+
		"\n          push: {url: "+url+", timeout: 10s, token: letmein}")
	// alice has no enrolment, so she is pushed and answers nothing.
	asked := 0
	c, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "alice",
		Auth: []cssh.AuthMethod{
			cssh.PublicKeys(key),
			cssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				asked += len(qs)
				return make([]string, len(qs)), nil
			}),
		},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("the unenrolled user was not pushed through: %v", err)
	}
	_ = c.Close()
	if asked != 0 {
		t.Errorf("the pushed user was asked %d questions", asked)
	}
	if n := len(svc.requests()); n != 1 {
		t.Errorf("%d notifications for the unenrolled user", n)
	}
	// bob is enrolled, so he is asked for a code and no notification is sent.
	code, err := mfaCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cssh.Dial("tcp", addr, &cssh.ClientConfig{
		User: "bob",
		Auth: []cssh.AuthMethod{
			cssh.PublicKeys(key),
			cssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				out := make([]string, len(qs))
				for i := range out {
					out[i] = code
				}
				return out, nil
			}),
		},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("the enrolled user could not use a code: %v", err)
	}
	_ = c2.Close()
	if n := len(svc.requests()); n != 1 {
		t.Errorf("%d notifications after the enrolled user signed in; a code is not a push", n)
	}
}

// mfaCode is the code for an enrolment's secret at this moment.
func mfaCode(secret []byte) (string, error) {
	return mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.Params{})
}
