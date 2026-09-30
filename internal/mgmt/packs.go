package mgmt

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"

	"github.com/rom/xproxy/internal/proxy"
)

// The behaviour packs over the control plane.
//
// Two calls, and the asymmetry between them is the point. Reading which packs
// are in force is the thing an operator does constantly, and it is free. Lifting
// a quarantine is a security decision -- somebody is saying "that address is
// fine, let it back onto the plant" -- so it is audited with the caller's
// kernel-reported credentials, like a ban being removed.
//
// There is no call to load, disable or edit a pack. A pack is a signed file and
// the configuration says which directory and which keys; a control plane that
// could add a detection at runtime would be a control plane that could add one
// nobody signed.

// maxPackBody bounds a release request. It carries an address.
const maxPackBody = 4 << 10

// releaseRequest is the body of POST /v1/packs/release.
type releaseRequest struct {
	// Address is the actor to let back in.
	Address string `json:"address"`
	// By is who is saying so, and Note why. Both reach the audit log: an
	// address let back onto a control network with no reason recorded is the
	// decision nobody can explain a year later.
	By   string `json:"by"`
	Note string `json:"note,omitempty"`
}

// listPacks answers GET /v1/packs.
func (s *Server) listPacks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.proxy.PackReport())
}

// releasePack answers POST /v1/packs/release.
func (s *Server) releasePack(w http.ResponseWriter, r *http.Request) {
	var body releaseRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxPackBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, 400, result{Error: "body: " + err.Error()})
		return
	}
	if body.Address == "" {
		body.Address = r.URL.Query().Get("address")
	}
	addr, err := netip.ParseAddr(body.Address)
	if err != nil {
		writeJSON(w, 400, result{Error: "address: " + err.Error()})
		return
	}
	released := s.proxy.ReleasePack(addr)
	s.audit(r, "pack_release", "address", addr.String(), "by", body.By,
		"note", body.Note, "held", released)
	if !released {
		writeJSON(w, 404, result{Error: "no pack is holding " + addr.String()})
		return
	}
	writeJSON(w, 200, result{OK: true})
}

// packRoutes registers the two calls.
func (s *Server) packRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/packs", s.listPacks)
	mux.HandleFunc("POST /v1/packs/release", s.releasePack)
}

// compile-time assertion that the report type is the proxy's, so a rename there
// reaches here rather than drifting.
var _ = proxy.PackReport{}
