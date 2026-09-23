package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

// mfaClient logs an operator in against the fake management API.
func mfaClient(t *testing.T, role string) (*fakeMgmt, *client) {
	t.Helper()
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir)})
	pw := map[string]string{"op": "operator-password-1", "view": "viewer-password-01"}[role]
	if st := c.login(role, pw); st != 200 {
		t.Fatalf("%s login: %d", role, st)
	}
	return fm, c
}

func TestMFAListingIsReadableByAViewer(t *testing.T) {
	_, c := mfaClient(t, "view")
	st, body := c.do("GET", "/api/mfa", nil, false)
	if st != 200 {
		t.Fatalf("list: %d %s", st, body)
	}
	var out []struct {
		Listener string `json:"listener"`
		Kind     string `json:"kind"`
		File     string `json:"file"`
		Users    []struct {
			User   string `json:"user"`
			Locked bool   `json:"locked"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if len(out) != 1 || out[0].Listener != "gate" || len(out[0].Users) != 2 {
		t.Fatalf("unexpected listing: %s", body)
	}
	if out[0].Users[1].User != "bob" || !out[0].Users[1].Locked {
		t.Fatalf("the locked user did not come through: %s", body)
	}
	// Nothing in the listing is a secret, but a viewer must not be able
	// to change anything either.
	for _, path := range []string{"/api/mfa/enrol", "/api/mfa/recovery", "/api/mfa/remove", "/api/mfa/unlock"} {
		if st, body := c.do("POST", path, map[string]string{"listener": "gate", "user": "alice"}, true); st != 403 {
			t.Fatalf("viewer %s: %d %s", path, st, body)
		}
	}
}

func TestMFAEnrolmentIsPassedOnUntouched(t *testing.T) {
	fm, c := mfaClient(t, "op")
	st, body := c.do("POST", "/api/mfa/enrol", map[string]any{
		"listener": " gate ", "user": " alice ", "issuer": "Sysctl", "digits": 8, "period_seconds": 60, "algo": "SHA256"}, true)
	if st != 200 {
		t.Fatalf("enrol: %d %s", st, body)
	}
	// The secret and the codes exist once; the GUI hands them on as
	// they arrived rather than keeping or reshaping them.
	for _, want := range []string{`"secret":"JBSWY3DPEHPK3PXPJBSWY3DPEH"`, `"otpauth://totp/`, `"show_once":true`,
		`"recovery":["abcde-fghij-klmno"]`, `"qr":"data:image/png;base64,`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("answer missing %s: %s", want, body)
		}
	}
	sent, _ := fm.mfaLast.Load().(string)
	var req map[string]any
	if err := json.Unmarshal([]byte(sent), &req); err != nil {
		t.Fatalf("what reached the socket was not JSON: %q", sent)
	}
	if req["listener"] != "gate" || req["user"] != "alice" {
		t.Fatalf("the names were not trimmed before forwarding: %q", sent)
	}
	if req["issuer"] != "Sysctl" || req["digits"] != 8.0 || req["period_seconds"] != 60.0 || req["algo"] != "SHA256" {
		t.Fatalf("the parameters did not reach the socket: %q", sent)
	}
}

func TestMFAActionsForwardAndAudit(t *testing.T) {
	fm, c := mfaClient(t, "op")
	for _, path := range []string{"/api/mfa/recovery", "/api/mfa/remove", "/api/mfa/unlock"} {
		st, body := c.do("POST", path, map[string]string{"listener": "gate", "user": "bob"}, true)
		if st != 200 {
			t.Fatalf("%s: %d %s", path, st, body)
		}
	}
	if n := fm.mfaCalls.Load(); n != 3 {
		t.Fatalf("calls forwarded: %d", n)
	}
	// A failure from the data plane reaches the operator with its own
	// message rather than a bare status.
	st, body := c.do("POST", "/api/mfa/remove", map[string]string{"listener": "gate", "user": "nobody"}, true)
	if st != 409 || !strings.Contains(string(body), "no such enrolment") {
		t.Fatalf("removing somebody who is not enrolled: %d %s", st, body)
	}
}

func TestMFARequestsThatAreNotRequests(t *testing.T) {
	_, c := mfaClient(t, "op")
	long := strings.Repeat("a", 300)
	for _, tc := range []struct {
		name string
		body any
	}{
		{"no user", map[string]string{"listener": "gate"}},
		{"no listener", map[string]string{"user": "alice"}},
		{"blank user", map[string]string{"listener": "gate", "user": "   "}},
		{"long user", map[string]string{"listener": "gate", "user": long}},
		{"long listener", map[string]string{"listener": long, "user": "alice"}},
		{"unknown field", map[string]string{"listener": "gate", "user": "alice", "secret": "x"}},
	} {
		if st, body := c.do("POST", "/api/mfa/enrol", tc.body, true); st != 400 {
			t.Errorf("%s: %d %s", tc.name, st, body)
		}
	}
	// A cross-site request is refused before any of that.
	if st, body := c.do("POST", "/api/mfa/remove", map[string]string{"listener": "gate", "user": "alice"}, false); st != 403 {
		t.Fatalf("without the header: %d %s", st, body)
	}
}
