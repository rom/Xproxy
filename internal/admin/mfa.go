package admin

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The second factor as the GUI changes it. Everything here forwards to
// the management API, which owns the enrolment files and audits each
// change with the calling process's credentials; the GUI adds its own
// audit line naming the operator who asked, since the socket only sees
// the GUI process.
//
// The mutating calls are limited to operators by the secure middleware,
// like every other POST. Listing is readable by a viewer: it names who
// is enrolled and whether they are locked out, never a secret — the
// file keeps hashes of the recovery codes and the enrolment secret is
// handed out once, at enrolment, and never read back.

// mfaChange is what the GUI's four actions take. It mirrors the
// management API's request, so it can be forwarded as it arrived after
// the fields have been checked.
type mfaChange struct {
	Listener string `json:"listener"`
	User     string `json:"user"`
	Issuer   string `json:"issuer,omitempty"`
	Digits   int    `json:"digits,omitempty"`
	Period   int    `json:"period_seconds,omitempty"`
	Algo     string `json:"algo,omitempty"`
}

// maxMFAName bounds the two strings a person types. The management API
// checks the name properly; this only keeps a silly request short.
const maxMFAName = 256

// readMFAChange reads the request and checks the two fields every call
// needs. A name the enrolment file could not hold is refused here so
// the socket never sees it.
func readMFAChange(w http.ResponseWriter, r *http.Request) (mfaChange, bool) {
	var req mfaChange
	if err := readJSONLimit(r, &req, 8<<10); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return req, false
	}
	req.Listener = strings.TrimSpace(req.Listener)
	req.User = strings.TrimSpace(req.User)
	if req.Listener == "" || req.User == "" {
		writeJSON(w, 400, map[string]any{"error": "listener and user are required"})
		return req, false
	}
	if len(req.Listener) > maxMFAName || len(req.User) > maxMFAName {
		writeJSON(w, 400, map[string]any{"error": "listener and user are limited to 256 bytes"})
		return req, false
	}
	return req, true
}

// mfaForward is the shape the four actions share: read, forward, audit.
// The answer of the management API is passed on as it came, because an
// enrolment's answer carries the secret and the recovery codes and this
// process has no business keeping them.
func (s *Server) mfaForward(name, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := readMFAChange(w, r)
		if !ok {
			return
		}
		sess := sessionFrom(r)
		var out json.RawMessage
		if err := s.client.Do(http.MethodPost, path, req, &out); err != nil {
			s.audit(r, sess, name, "listener", req.Listener, "target", req.User, "ok", false, "err", err.Error())
			writeJSON(w, 409, map[string]any{"error": err.Error()})
			return
		}
		s.audit(r, sess, name, "listener", req.Listener, "target", req.User, "ok", true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}
}
