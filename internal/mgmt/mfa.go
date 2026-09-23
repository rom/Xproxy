package mgmt

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/qr"
)

// The second factor as the control plane changes it. Enrolling and
// removing a person are things an operator does, so they belong here
// rather than in a file somebody has to find and a reload nobody
// remembers to run.
//
// Every one of these is audited with the caller's kernel-reported
// credentials, like every other mutating call: who took a person's
// second factor away is exactly the kind of thing worth being able to
// answer afterwards.

// maxMFABody bounds a request. These carry a name and a few numbers.
const maxMFABody = 8 << 10

// mfaRequest is what the three mutating calls take.
type mfaRequest struct {
	Listener string `json:"listener"`
	User     string `json:"user"`
	// Issuer is what an authenticator shows beside the account. It
	// defaults to the proxy rather than being required.
	Issuer string `json:"issuer,omitempty"`
	// Digits, Period and Algo are the enrolment's parameters, and are
	// left at the defaults when they are zero.
	Digits int    `json:"digits,omitempty"`
	Period int    `json:"period_seconds,omitempty"`
	Algo   string `json:"algo,omitempty"`
}

// params turns the request's fields into the enrolment's.
func (m mfaRequest) params() mfa.Params {
	return mfa.Params{
		Digits: m.Digits,
		Period: time.Duration(m.Period) * time.Second,
		Algo:   strings.ToUpper(strings.TrimSpace(m.Algo)),
	}
}

// MFAEnrolled is what an enrolment returns. It is the only time the
// secret and the recovery codes exist outside the operator's hands, so
// the answer says so and the caller is expected to show them once.
type MFAEnrolled struct {
	OK bool `json:"ok"`
	// Secret is the shared secret in base32, and URI the otpauth form
	// an authenticator reads from a QR code.
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	// QR is the URI again as a PNG `data:` URI, because typing a
	// twenty-six character secret into a telephone by hand is how
	// enrolments go wrong. It is empty when the URI is too long for a
	// symbol, which nothing this makes comes near; a caller that has
	// the URI needs nothing from it.
	QR string `json:"qr,omitempty"`
	// Recovery are the single-use codes. The file keeps only hashes of
	// them, so this is the one time they can be read.
	Recovery []string `json:"recovery"`
	// ShowOnce says what it says: nothing here can be recovered later.
	ShowOnce bool `json:"show_once"`
}

func (s *Server) mfaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/mfa", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, s.proxy.MFA())
	})
	mux.HandleFunc("POST /v1/mfa/enrol", s.mfaEnrol)
	mux.HandleFunc("POST /v1/mfa/recovery", s.mfaRecovery)
	mux.HandleFunc("POST /v1/mfa/remove", s.mfaAction("mfa_remove", func(m mfaRequest) error {
		return s.proxy.MFARemove(m.Listener, m.User)
	}))
	mux.HandleFunc("POST /v1/mfa/unlock", s.mfaAction("mfa_unlock", func(m mfaRequest) error {
		_, err := s.proxy.MFAUnlock(m.Listener, m.User)
		return err
	}))
}

// readMFARequest reads and bounds one.
func readMFARequest(w http.ResponseWriter, r *http.Request) (mfaRequest, bool) {
	var m mfaRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMFABody+1))
	if err != nil || len(body) > maxMFABody {
		writeJSON(w, 400, result{Error: "request too long"})
		return m, false
	}
	if err := json.Unmarshal(body, &m); err != nil {
		writeJSON(w, 400, result{Error: "not JSON: " + err.Error()})
		return m, false
	}
	if m.Listener == "" || m.User == "" {
		writeJSON(w, 400, result{Error: "listener and user are required"})
		return m, false
	}
	return m, true
}

// mfaAction is the shape the two plain actions share: read, do, audit.
func (s *Server) mfaAction(name string, fn func(mfaRequest) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, ok := readMFARequest(w, r)
		if !ok {
			return
		}
		s.auditMFA(w, r, name, m, fn(m), nil)
	}
}

// mfaEnrol gives a person a factor and answers with what to show them
// once.
func (s *Server) mfaEnrol(w http.ResponseWriter, r *http.Request) {
	m, ok := readMFARequest(w, r)
	if !ok {
		return
	}
	secret, uri, recovery, err := s.proxy.MFAEnrol(m.Listener, m.User, m.Issuer, m.params())
	s.auditMFA(w, r, "mfa_enrol", m, err, func() any {
		return MFAEnrolled{OK: true, Secret: secret, URI: uri, QR: qrOf(uri), Recovery: recovery, ShowOnce: true}
	})
}

// mfaRecovery replaces a person's recovery codes.
func (s *Server) mfaRecovery(w http.ResponseWriter, r *http.Request) {
	m, ok := readMFARequest(w, r)
	if !ok {
		return
	}
	codes, err := s.proxy.MFARecovery(m.Listener, m.User)
	s.auditMFA(w, r, "mfa_recovery", m, err, func() any {
		return MFAEnrolled{OK: true, Recovery: codes, ShowOnce: true}
	})
}

// qrOf draws the URI as a symbol an authenticator can be pointed at.
// A failure is not one: the URI is in the same answer, and an operator
// reading out a secret is worse off without a picture but not stuck.
func qrOf(uri string) string {
	if uri == "" {
		return ""
	}
	code, err := qr.Encode(uri)
	if err != nil {
		return ""
	}
	// Four modules of quiet zone is what the standard asks for, and
	// four pixels a module keeps a telephone camera happy at arm's
	// length without making the answer large.
	data, err := code.DataURI(4, 4)
	if err != nil {
		return ""
	}
	return data
}

// auditMFA writes the audit line and the answer. The line names the
// listener and the person but never what was handed out.
func (s *Server) auditMFA(w http.ResponseWriter, r *http.Request, name string, m mfaRequest, err error, body func() any) {
	peer := peerFromContext(r.Context())
	attrs := []any{"action", name, "listener", m.Listener, "user", m.User,
		"peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID, "peer_known", peer.OK}
	if err != nil {
		s.logs.Audit.Warn("management action failed", append(attrs, "err", err.Error())...)
		writeJSON(w, 409, result{Error: err.Error()})
		return
	}
	s.logs.Audit.Info("management action", attrs...)
	if body != nil {
		writeJSON(w, 200, body())
		return
	}
	writeJSON(w, 200, result{OK: true})
}
