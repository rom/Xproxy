package admin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Work orders from the web interface.
//
// The one thing this file does that a plain pass-through would not: the
// filer's name comes from the session, not from the browser. The interface
// knows who is logged in, and a work order whose `by` a page could set would
// be a record naming whoever the page felt like. Everything else -- the
// reference, the device, the window, the note -- is the operator's to say, and
// is validated by the data plane rather than here, so one set of rules decides
// what a work order may be whichever way it was filed.
//
// Filing one permits nothing. That is stated in the interface too, because the
// mistake worth preventing is an operator filing a work order and believing
// the download is now approved.

// workOrderForm is what the Plant screen posts.
type workOrderForm struct {
	Reference string `json:"reference"`
	Device    string `json:"device"`
	Listener  string `json:"listener,omitempty"`
	Note      string `json:"note,omitempty"`
	Duration  string `json:"duration"`
	Start     string `json:"start,omitempty"`
}

// fileWorkOrder posts one to the data plane as the logged-in operator.
func (s *Server) fileWorkOrder(w http.ResponseWriter, r *http.Request) {
	var form workOrderForm
	if err := readJSON(r, &form); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	sess := sessionFrom(r)
	body := map[string]any{
		"reference": strings.TrimSpace(form.Reference),
		"device":    strings.TrimSpace(form.Device),
		"duration":  strings.TrimSpace(form.Duration),
		// The session decides this, never the page.
		"by": sess.User,
	}
	if v := strings.TrimSpace(form.Listener); v != "" {
		body["listener"] = v
	}
	if v := strings.TrimSpace(form.Note); v != "" {
		body["note"] = v
	}
	if v := strings.TrimSpace(form.Start); v != "" {
		body["start"] = v
	}
	var out json.RawMessage
	if err := s.client.Do(http.MethodPost, "/v1/workorders", body, &out); err != nil {
		s.audit(r, sess, "work_order_filed", "reference", body["reference"],
			"device", body["device"], "ok", false, "err", err.Error())
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	s.audit(r, sess, "work_order_filed", "reference", body["reference"],
		"device", body["device"], "duration", body["duration"], "ok", true)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// closeWorkOrder ends one early, again as the logged-in operator.
func (s *Server) closeWorkOrder(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.URL.Query().Get("reference"))
	if ref == "" {
		writeJSON(w, 400, map[string]any{"error": "reference required"})
		return
	}
	sess := sessionFrom(r)
	q := url.Values{"reference": {ref}, "by": {sess.User}}
	if note := strings.TrimSpace(r.URL.Query().Get("note")); note != "" {
		q.Set("note", note)
	}
	var out json.RawMessage
	if err := s.client.Do(http.MethodDelete, "/v1/workorders?"+q.Encode(), nil, &out); err != nil {
		s.audit(r, sess, "work_order_closed", "reference", ref, "ok", false, "err", err.Error())
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	s.audit(r, sess, "work_order_closed", "reference", ref, "ok", true)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}
