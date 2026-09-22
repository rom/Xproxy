package proxy

import (
	"context"
	"net/netip"
	"strings"

	"github.com/rom/xproxy/internal/streamscan"
)

// yaraGuard and yaraStream are streamscan's, under the names the engine
// has always used for them.
type (
	yaraGuard  = streamscan.Guard
	yaraStream = streamscan.Stream
)

var newYARAGuard = streamscan.New

// report logs a match and counts it. It returns true when the
// connection should be closed.
func (t *tcpServer) yaraReport(s *yaraStream, ip netip.Addr, sni string) bool {
	ms := s.Matches()
	if len(ms) == 0 {
		return false
	}
	names := make([]string, 0, len(ms))
	tags := map[string]bool{}
	for _, m := range ms {
		names = append(names, m.Rule)
		for _, tag := range m.Tags {
			tags[tag] = true
		}
	}
	tagList := make([]string, 0, len(tags))
	for tag := range tags {
		tagList = append(tagList, tag)
	}
	t.s.stats.YARAMatches.Add(1)
	action := s.Policy().Action
	t.s.logs.SecurityEvent(context.Background(), action, "yara_match",
		"listener", t.cfg.Name, "client_ip", ip.String(), "sni", sni, "proto", "tcp",
		"direction", s.Direction, "rules", strings.Join(names, ","), "tags", strings.Join(tagList, ","),
		"offset", ms[0].Offset)
	if action != "close" {
		return false
	}
	if bl := t.s.bans.Load(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "yara")
	}
	return true
}
