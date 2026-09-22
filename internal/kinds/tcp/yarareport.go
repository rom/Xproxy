package tcp

import (
	"context"
	"net/netip"
	"strings"

	"github.com/rom/xproxy/internal/streamscan"
)

// report logs a match and counts it. It returns true when the
// connection should be closed.
func (t *server) yaraReport(s *streamscan.Stream, ip netip.Addr, sni string) bool {
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
	t.engine.Counters().YARAMatches.Add(1)
	action := s.Policy().Action
	t.engine.Logs().SecurityEvent(context.Background(), action, "yara_match",
		"listener", t.cfg.Name, "client_ip", ip.String(), "sni", sni, "proto", "tcp",
		"direction", s.Direction, "rules", strings.Join(names, ","), "tags", strings.Join(tagList, ","),
		"offset", ms[0].Offset)
	if action != "close" {
		return false
	}
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "yara")
	}
	return true
}
