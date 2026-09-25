package mgmt

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/proxy"
)

// The device inventory over the control plane.
//
// An inventory nobody can read is a file on disk. These are the three things an
// operator does with one: look at it, look up the device in a log line, and say
// "this is the estate" so that everything after it is a finding.
//
// Freezing and thawing a baseline are mutating calls, so both are audited with
// the caller's kernel-reported credentials, like a ban. Deciding what counts as
// normal on a network is a security decision, and a security decision with no
// record of who made it is the kind that nobody can explain a year later.

// AssetReport is what GET /v1/assets answers: the summary, then the devices.
//
// The summary comes first and is always present, because the list can be
// thousands of lines and the numbers are what an operator reads.
type AssetReport struct {
	Summary *proxy.AssetSummary `json:"summary"`
	Roles   []string            `json:"known_roles"`
	Assets  []*assets.Asset     `json:"assets"`
	// Matched is how many assets the filter selected, before top cut the
	// list. An operator who asked for the top 50 of 900 needs to know it
	// was 900.
	Matched int `json:"matched"`
}

// assetFilter is the query, compiled once.
type assetFilter struct {
	role     string
	listener string
	proto    string
	vendor   string
	onlyNew  bool
	changed  bool
	top      int
}

func (f assetFilter) keep(a *assets.Asset) bool {
	switch {
	case f.role != "" && !strings.EqualFold(string(a.Class.Role), f.role):
		return false
	case f.onlyNew && !a.New:
		return false
	case f.changed && len(a.Changes) == 0:
		return false
	case f.vendor != "" && !strings.Contains(strings.ToLower(a.Vendor), strings.ToLower(f.vendor)):
		return false
	case f.proto != "" && a.Protos[f.proto] == 0:
		return false
	case f.listener != "" && !contains(a.Listeners, f.listener):
		return false
	}
	return true
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// listAssets answers GET /v1/assets.
//
// An id names one device and answers 404 when there is none, which is the
// lookup an operator does from a log line. Everything else is a filter over
// the list.
func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	inv := s.proxy.Assets()
	if inv == nil {
		writeJSON(w, 404, result{Error: "asset inventory is not configured"})
		return
	}
	q := r.URL.Query()
	if key := q.Get("id"); key != "" {
		a, ok := inv.Get(key)
		if !ok {
			writeJSON(w, 404, result{Error: "no asset with that identifier, address or hardware address"})
			return
		}
		writeJSON(w, 200, a)
		return
	}
	f := assetFilter{role: q.Get("role"), listener: q.Get("listener"),
		proto: q.Get("proto"), vendor: q.Get("vendor"),
		onlyNew: q.Get("new") == "1", changed: q.Get("changed") == "1"}
	// A role that is not a role is refused rather than matching nothing: a
	// filter that silently answers "no devices" reads as "the estate is
	// clean", which is the wrong answer to a typo.
	if f.role != "" {
		if _, ok := assets.RoleOf(f.role); !ok {
			writeJSON(w, 400, result{Error: "role: not a known role, see known_roles"})
			return
		}
	}
	if v := q.Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSON(w, 400, result{Error: "top: not a count"})
			return
		}
		f.top = n
	}
	all := inv.List()
	out := make([]*assets.Asset, 0, len(all))
	for _, a := range all {
		if f.keep(a) {
			out = append(out, a)
		}
	}
	rep := AssetReport{Summary: s.proxy.AssetReport(), Roles: assets.RoleNames(), Matched: len(out)}
	if f.top > 0 && len(out) > f.top {
		out = out[:f.top]
	}
	rep.Assets = out
	writeJSON(w, 200, rep)
}

// freezeAssets answers POST /v1/assets/baseline: this is the estate.
func (s *Server) freezeAssets(w http.ResponseWriter, r *http.Request) {
	inv := s.proxy.Assets()
	if inv == nil {
		writeJSON(w, 404, result{Error: "asset inventory is not configured"})
		return
	}
	n := inv.Freeze()
	s.audit(r, "asset_baseline_freeze", "assets", n)
	writeJSON(w, 200, map[string]any{"frozen": true, "baseline_size": n})
}

// thawAssets answers DELETE /v1/assets/baseline. Nothing is a new device
// afterwards, which is why forgetting a baseline is audited as loudly as
// taking one.
func (s *Server) thawAssets(w http.ResponseWriter, r *http.Request) {
	inv := s.proxy.Assets()
	if inv == nil {
		writeJSON(w, 404, result{Error: "asset inventory is not configured"})
		return
	}
	n, was := inv.Frozen()
	inv.Thaw()
	s.audit(r, "asset_baseline_thaw", "was_frozen", was, "baseline_size", n)
	writeJSON(w, 200, map[string]any{"frozen": false, "was_frozen": was})
}
