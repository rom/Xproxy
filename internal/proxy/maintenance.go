package proxy

import (
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// compiledMaintenance is the maintenance-mode policy for a generation.
type compiledMaintenance struct {
	status      int
	retryAfter  string
	message     string
	allow       []netip.Prefix
	allowHeader string // canonical name
	allowValue  string
}

func newMaintenance(m *config.Maintenance) *compiledMaintenance {
	cm := &compiledMaintenance{
		status:     m.Status,
		retryAfter: strconv.Itoa(int(m.RetryAfter.D().Seconds())),
		message:    m.Message,
		allow:      netutil.ParsePrefixes(m.AllowCIDRs),
	}
	if h := m.AllowHeader; h != "" {
		if name, val, ok := strings.Cut(h, ":"); ok {
			cm.allowHeader = http.CanonicalHeaderKey(strings.TrimSpace(name))
			cm.allowValue = strings.TrimSpace(val)
		}
	}
	return cm
}

// exempt reports whether a request bypasses maintenance: an allowlisted
// address or the bypass header.
func (cm *compiledMaintenance) exempt(ip netip.Addr, r *http.Request) bool {
	if netutil.Contains(cm.allow, ip) {
		return true
	}
	// The bypass value is a shared secret: compare in constant time.
	if cm.allowHeader != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get(cm.allowHeader)), []byte(cm.allowValue)) == 1 {
		return true
	}
	return false
}

// serve writes the maintenance response.
func (cm *compiledMaintenance) serve(rw http.ResponseWriter, r *http.Request) {
	h := rw.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if cm.retryAfter != "0" {
		h.Set("Retry-After", cm.retryAfter)
	}
	rw.WriteHeader(cm.status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write([]byte(cm.message + "\n"))
	}
}

// Maintenance reports the runtime maintenance state; on toggles it when
// non-nil. It returns the resulting state and whether a policy is
// configured.
func (s *Server) Maintenance(on *bool) (state, configured bool) {
	configured = s.rt.Load().maintenance != nil
	if on != nil {
		s.maintenance.Store(*on)
	}
	return s.maintenance.Load(), configured
}
