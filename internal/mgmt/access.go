package mgmt

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/access"
)

// Just-in-time access as the control plane works it: asking for a window,
// approving somebody else's ask, refusing one, and taking one back.
//
// Every call is audited with the caller's kernel-reported credentials, as every
// mutating call here is -- and for these that is the point rather than a
// formality. The ledger records the *name* each act was made under, because that
// is what four eyes is enforced on and what an investigation reads; the audit
// log records the uid, gid and pid behind it. The two together answer "who
// approved this" twice over, and they can disagree, which is itself worth
// seeing: an estate where everybody reaches the socket as root gets its
// accountability from the names and from the socket's group rather than from the
// kernel, and it should know that.

// maxAccessBody bounds a request. These carry a few names and a duration.
const maxAccessBody = 8 << 10

// AccessReport is what GET /v1/access answers.
type AccessReport struct {
	Stats  access.Stats  `json:"stats"`
	Grants []access.View `json:"grants"`
}

// accessRequest is the body of POST /v1/access.
type accessRequest struct {
	// Subject is who the access is for, Listener and Target where.
	Subject  string `json:"subject"`
	Listener string `json:"listener"`
	Target   string `json:"target"`
	// Reason is required: a trail of approvals with no reasons in it
	// answers nothing.
	Reason string `json:"reason"`
	// By is who is asking. It is a name rather than a credential because
	// the socket is the credential; see the note at the top.
	By string `json:"by"`
	// Duration is how long the window lasts (Go duration), and Start an
	// optional RFC 3339 time for a window that opens later.
	Duration string `json:"duration"`
	Start    string `json:"start,omitempty"`
	// MaxUses bounds the sessions the grant may open; 0 leaves the window
	// as the only bound.
	MaxUses int `json:"max_uses,omitempty"`
}

// accessAct is the body of the approve, deny and revoke calls.
type accessAct struct {
	ID   string `json:"id"`
	By   string `json:"by"`
	Note string `json:"note,omitempty"`
}

// ledger returns the access ledger, answering 404 when the estate has none.
func (s *Server) ledger(w http.ResponseWriter) *access.Ledger {
	l := s.proxy.Access()
	if l == nil {
		writeJSON(w, 404, result{Error: "just-in-time access is not configured (no access section)"})
		return nil
	}
	return l
}

func (s *Server) listAccess(w http.ResponseWriter, r *http.Request) {
	l := s.ledger(w)
	if l == nil {
		return
	}
	if id := r.URL.Query().Get("id"); id != "" {
		v, ok := l.Get(id)
		if !ok {
			writeJSON(w, 404, result{Error: "no grant with that id"})
			return
		}
		writeJSON(w, 200, v)
		return
	}
	grants := l.Grants()
	if state := r.URL.Query().Get("state"); state != "" {
		kept := grants[:0]
		for _, g := range grants {
			if strings.EqualFold(string(g.State), state) {
				kept = append(kept, g)
			}
		}
		grants = kept
	}
	writeJSON(w, 200, AccessReport{Stats: l.Stats(), Grants: grants})
}

// askAccess is POST /v1/access: a request for a window, which is not access
// until somebody else approves it.
func (s *Server) askAccess(w http.ResponseWriter, r *http.Request) {
	l := s.ledger(w)
	if l == nil {
		return
	}
	var body accessRequest
	if !decodeAccess(w, r, &body) {
		return
	}
	d, err := time.ParseDuration(strings.TrimSpace(body.Duration))
	if err != nil {
		writeJSON(w, 400, result{Error: "duration: " + err.Error()})
		return
	}
	start := time.Now()
	if body.Start != "" {
		if start, err = time.Parse(time.RFC3339, strings.TrimSpace(body.Start)); err != nil {
			writeJSON(w, 400, result{Error: "start: " + err.Error()})
			return
		}
	}
	g, err := l.Request(access.Request{
		Subject: body.Subject, Listener: body.Listener, Target: body.Target, Reason: body.Reason,
		By: body.By, NotBefore: start, Expires: start.Add(d), MaxUses: body.MaxUses,
	})
	if err != nil {
		writeJSON(w, statusFor(err), result{Error: err.Error()})
		return
	}
	s.audit(r, "access_request", "grant", g.ID, "subject", g.Subject, "listener", g.Listener,
		"target", g.Target, "by", g.By, "reason", g.Reason, "expires", g.Expires.UTC().Format(time.RFC3339),
		"needs_approvals", g.NeedApprovals)
	writeJSON(w, 200, g)
}

// actOnAccess is the approve, deny and revoke calls, which differ only in which
// method of the ledger they call and what the audit line is named.
func (s *Server) actOnAccess(action string, fn func(l *access.Ledger, a accessAct) (*access.Grant, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := s.ledger(w)
		if l == nil {
			return
		}
		var body accessAct
		if !decodeAccess(w, r, &body) {
			return
		}
		if body.ID == "" {
			body.ID = r.URL.Query().Get("id")
		}
		g, err := fn(l, body)
		if err != nil {
			s.audit(r, action+"_refused", "grant", body.ID, "by", body.By, "err", err.Error())
			writeJSON(w, statusFor(err), result{Error: err.Error()})
			return
		}
		s.audit(r, action, "grant", g.ID, "subject", g.Subject, "listener", g.Listener, "target", g.Target,
			"by", body.By, "note", body.Note, "state", string(g.State(time.Now())),
			"approvals", len(g.Approvals), "needs_approvals", g.NeedApprovals)
		writeJSON(w, 200, g)
	}
}

// decodeAccess reads a bounded JSON body.
func decodeAccess(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxAccessBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		writeJSON(w, 400, result{Error: "body: " + err.Error()})
		return false
	}
	return true
}

// statusFor maps a ledger error to a status, so a client can tell a refusal it
// can do something about from one it cannot.
func statusFor(err error) int {
	switch {
	case errors.Is(err, access.ErrUnknownGrant):
		return 404
	case errors.Is(err, access.ErrSelfApproval), errors.Is(err, access.ErrDuplicateApproval):
		// 403 rather than 400: the request is well formed and this person
		// may not make it.
		return 403
	case errors.Is(err, access.ErrNotOpen):
		return 409
	case errors.Is(err, access.ErrTooMany):
		return 429
	}
	return 400
}

// accessRoutes registers the five calls.
func (s *Server) accessRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/access", s.listAccess)
	mux.HandleFunc("POST /v1/access", s.askAccess)
	mux.HandleFunc("POST /v1/access/approve", s.actOnAccess("access_approve",
		func(l *access.Ledger, a accessAct) (*access.Grant, error) { return l.Approve(a.ID, a.By, a.Note) }))
	mux.HandleFunc("POST /v1/access/deny", s.actOnAccess("access_deny",
		func(l *access.Ledger, a accessAct) (*access.Grant, error) { return l.Deny(a.ID, a.By, a.Note) }))
	mux.HandleFunc("POST /v1/access/revoke", s.actOnAccess("access_revoke",
		func(l *access.Ledger, a accessAct) (*access.Grant, error) { return l.Revoke(a.ID, a.By, a.Note) }))
}
