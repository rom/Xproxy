package proxy

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/tlsconf"
)

// Refusing a client in the ClientHello.
//
// Everything else in this proxy answers a request: the handshake runs,
// a certificate is chosen, keys are agreed, the request is parsed, and
// then it is refused. For a client already known to be unwelcome that
// is a key exchange spent on saying no, and an answer a scanner can
// read — a status, a page, a header set, a certificate. Refusing here
// costs a hello and says nothing at all.

// handshakePolicy is the compiled handshake section.
type handshakePolicy struct {
	refuseBanned bool
	log          bool
	// exact holds full fingerprints, keyed by value; ja4Only and
	// ja3Only narrow an entry that named which kind it is.
	exact map[string]bool
	ja4   map[string]bool
	ja3   map[string]bool
	// prefixes are JA4 entries ending in "*", which name a family of
	// clients without pinning every extension order.
	prefixes []string

	refused atomic.Uint64
}

func newHandshakePolicy(c *config.Handshake) *handshakePolicy {
	if c == nil {
		return nil
	}
	p := &handshakePolicy{
		refuseBanned: c.RefuseBanned, log: c.LogRefusals(),
		exact: map[string]bool{}, ja4: map[string]bool{}, ja3: map[string]bool{},
	}
	for _, f := range c.DenyFingerprints {
		switch {
		case strings.HasPrefix(f, "ja4:"):
			v := strings.TrimPrefix(f, "ja4:")
			if pre, ok := strings.CutSuffix(v, "*"); ok {
				p.prefixes = append(p.prefixes, pre)
				continue
			}
			p.ja4[v] = true
		case strings.HasPrefix(f, "ja3:"):
			p.ja3[strings.TrimPrefix(f, "ja3:")] = true
		default:
			if pre, ok := strings.CutSuffix(f, "*"); ok {
				p.prefixes = append(p.prefixes, pre)
				continue
			}
			p.exact[f] = true
		}
	}
	if !p.refuseBanned && len(p.exact) == 0 && len(p.ja4) == 0 && len(p.ja3) == 0 && len(p.prefixes) == 0 {
		return nil
	}
	return p
}

// denies reports whether a fingerprint is on the static list.
func (p *handshakePolicy) denies(fp tlsconf.Fingerprint) bool {
	if p.exact[fp.JA4] || p.exact[fp.JA3] || p.ja4[fp.JA4] || p.ja3[fp.JA3] {
		return true
	}
	for _, pre := range p.prefixes {
		if strings.HasPrefix(fp.JA4, pre) {
			return true
		}
	}
	return false
}

// refuse is installed on every TLS listener. It runs inside the
// handshake, so it does no allocation it can avoid and asks the ban
// list the cheap question first.
func (s *Server) refuseHandshake(remote net.Addr, fp tlsconf.Fingerprint) string {
	p := s.handshake.Load()
	if p == nil {
		return ""
	}
	reason := ""
	if p.denies(fp) {
		reason = "fingerprint"
	} else if p.refuseBanned {
		if bl := s.bans.Load(); bl != nil {
			ip := netutil.PeerAddr(remote)
			if ip.IsValid() && bl.BannedClient(ip, fp.JA4) {
				reason = "banned"
			}
		}
	}
	if reason == "" {
		return ""
	}
	p.refused.Add(1)
	s.stats.HandshakesRefused.Add(1)
	if p.log {
		// There is no request to attach this to: the connection never
		// became one, which is the point.
		s.logs.Security.Info("deny", "event", "handshake", "reason", "handshake", "detail", reason,
			"client_ip", netutil.PeerAddr(remote).String(), "ja3", fp.JA3, "ja4", fp.JA4)
	}
	return reason
}

// HandshakeStatus is the management view of the pre-handshake policy.
type HandshakeStatus struct {
	Enabled      bool   `json:"enabled"`
	RefuseBanned bool   `json:"refuse_banned"`
	Fingerprints int    `json:"fingerprints"`
	Refused      uint64 `json:"refused"`
}

// Handshake reports the pre-handshake refusal policy and its counter.
func (s *Server) Handshake() HandshakeStatus {
	p := s.handshake.Load()
	if p == nil {
		return HandshakeStatus{}
	}
	return HandshakeStatus{
		Enabled: true, RefuseBanned: p.refuseBanned,
		Fingerprints: len(p.exact) + len(p.ja4) + len(p.ja3) + len(p.prefixes),
		Refused:      p.refused.Load(),
	}
}
