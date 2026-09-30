package proxy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rom/xproxy/internal/attack"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/packs"
)

// The behaviour packs, where the engine meets the daemon.
//
// Two connections, and they are both at choke points that already existed.
//
// The events come from logging.SecurityEvent, the one place every refusal,
// behavioural finding and engineering operation in this project passes
// through. The server registers itself as that stream's watcher at start, so a
// kind gains pack coverage by having a refusal reason rather than by
// remembering to call anything.
//
// The quarantine, where an operator turned enforcement on and a pack declared
// it, is asked about in internal/admit -- the one place every kind admits a
// client. So a held actor is held on every listener of this daemon and not only
// on the one that tripped the pack, which is the point: a tool that was refused
// on Modbus tries S7 next.

// newPacks loads the pack directory and builds the engine. A pack that does not
// load stops the daemon, with the file and the reason named: a directory of
// signed detections is small and curated, and a file in it that does not pass
// is a mistake somebody made minutes ago rather than a reason to start with a
// detection missing and nothing but a counter to say so.
func newPacks(c *config.Config) (*packs.Engine, []string, error) {
	if !c.PacksEnabled() {
		return nil, nil, nil
	}
	pc := c.Packs
	t := packs.Trust{AllowUnsigned: pc.AllowUnsigned}
	for _, k := range pc.Keys {
		var (
			key packs.Key
			err error
		)
		if k.File != "" {
			key, err = packs.ReadKeyFile(k.Name, k.File)
		} else {
			key, err = packs.ParseKey(k.Name, k.Key)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("packs.keys: %w", err)
		}
		t.Keys = append(t.Keys, key)
	}
	rep, err := packs.Load(pc.Directory, t)
	if err != nil {
		return nil, nil, fmt.Errorf("packs: %w", err)
	}
	notes := make([]string, 0, 4)
	for _, f := range rep.Unsigned {
		notes = append(notes, "pack loaded unsigned: "+f)
	}
	for _, f := range rep.Superseded {
		notes = append(notes, "pack superseded by a higher revision: "+f)
	}
	e := packs.New(rep.Packs, packs.Options{
		Enforce:  pc.Enforce,
		Disabled: pc.Disabled,
		Bounds: packs.Bounds{
			MaxActors:      pc.MaxActors,
			MaxQuarantined: pc.MaxQuarantined,
		},
	})
	return e, notes, nil
}

// Packs implements Host: the pack engine, nil when there is none. A nil engine
// answers nothing and quarantines nobody, so a kind holds it without checking.
func (s *Server) Packs() *packs.Engine { return s.packs }

// SecurityEvent implements logging.SecurityWatcher: feed one event to the packs
// and report what they made of it.
//
// The attributes are read for the two fields a pack needs and nothing else --
// the client address and the listener kind -- because the pack language can ask
// about those and no more. Everything else in a security event is a string a
// peer chose, and a detection that compared one would be a detection an
// attacker writes half of.
func (s *Server) SecurityEvent(action, reason string, attrs []any) {
	e := s.packs
	if !e.On() {
		return
	}
	ev := packs.Event{Action: action, Reason: reason}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, ok := attrs[i].(string)
		if !ok {
			continue
		}
		switch k {
		case "client_ip":
			if v, ok := attrs[i+1].(string); ok {
				ev.Actor, _ = netip.ParseAddr(v)
			}
		case "proto":
			if v, ok := attrs[i+1].(string); ok {
				ev.Kind = v
			}
		case "listener":
			if v, ok := attrs[i+1].(string); ok {
				ev.Listener = v
			}
		}
	}
	if !ev.Actor.IsValid() {
		// A redacted address, an event about the estate rather than about a
		// peer, or a kind that names the client something else. There is
		// nothing for a per-actor detection to key on, and inventing a key
		// would collapse every such event onto one actor.
		return
	}
	for _, f := range e.Observe(ev) {
		s.reportPack(f)
	}
}

// reportPack is what a match is worth: a security event of its own, a counter, a
// fact in the cross-listener window, and -- where the pack and the operator both
// allowed it -- the note that the actor is held.
//
// The event's reason is the pack's, `pack_<id>`, so a SIEM filters on one pack;
// its technique is the pack's own declaration, which is why a pack may only name
// a technique this build already has in internal/attack.
func (s *Server) reportPack(f packs.Finding) {
	s.stats.PackMatch(f.Pack, string(f.Severity))
	attrs := []any{
		"pack", f.Pack, "pack_name", f.Name,
		"severity", string(f.Severity),
		"client_ip", f.Actor.String(),
		"signals", strings.Join(f.Signals, ","),
		"detail", f.Detail(),
	}
	// The technique comes from the pack rather than from internal/attack's
	// table, because a pack identifier is not in that table and cannot be: the
	// directory is loaded at start and the table is compiled in. What keeps the
	// two honest is the other direction -- a pack may only name a technique the
	// table already has, checked when it loads -- so the identifier on this
	// event is one docs/ATTACK.md documents.
	if t, ok := attack.Get(f.Technique); ok {
		ts := []attack.Technique{t}
		attrs = append(attrs,
			"technique", attack.IDs(ts),
			"technique_name", attack.Names(ts),
			"tactic", attack.Tactics(ts),
			"matrix", attack.Matrices(ts))
	}
	if len(f.Kinds) > 0 {
		attrs = append(attrs, "protocols", strings.Join(f.Kinds, ","))
	}
	action := "alert"
	if f.Denied {
		action = "quarantine"
		attrs = append(attrs, "quarantine", true)
	}
	s.logs.SecurityEvent(context.Background(), action, f.Reason(), attrs...)
	s.ObserveFact(f.Actor, correlate.Fact{
		Class: correlate.ClassRefused, Kind: "packs", Listener: f.Pack,
		Detail: f.Detail(),
	})
}

// PackView is one pack as a report shows it: what it is, what it may do, and
// who vouched for the file it came from.
type PackView struct {
	ID          string   `json:"id"`
	Revision    int      `json:"revision"`
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Technique   string   `json:"technique"`
	Matrix      string   `json:"matrix"`
	Tactic      string   `json:"tactic"`
	Severity    string   `json:"severity"`
	Enforcement string   `json:"enforcement"`
	Kinds       []string `json:"kinds"`
	Window      string   `json:"window"`
	Signals     []string `json:"signals"`
	Ordered     bool     `json:"ordered"`
	AcrossKinds int      `json:"across_kinds,omitempty"`
	References  []string `json:"references,omitempty"`
	// Source is the file, and Signer the key that signed it -- empty where the
	// pack was loaded unsigned, which is the field an audit reads.
	Source string `json:"source"`
	Signer string `json:"signer,omitempty"`
	// Matches is how many findings this pack has made since start.
	Matches uint64 `json:"matches"`
}

// PackReport is what the control plane answers about the packs: the engine's own
// numbers, then the packs in force.
type PackReport struct {
	Status packs.Status `json:"status"`
	Packs  []PackView   `json:"packs"`
}

// PackReport builds it.
func (s *Server) PackReport() PackReport {
	rep := PackReport{Status: s.packs.Status()}
	for _, p := range s.packs.Packs() {
		v := PackView{
			ID: p.ID, Revision: p.Revision, Name: p.Name, Summary: p.Summary,
			Technique: p.Technique, Severity: string(p.Severity),
			Enforcement: string(p.Enforcement), Kinds: p.Kinds,
			Window:  p.Detect.Window.String(),
			Ordered: p.Detect.Ordered, AcrossKinds: p.Detect.AcrossKinds,
			References: p.References, Source: p.Source, Signer: p.Signer,
			Matches: rep.Status.Matches[p.ID],
		}
		if t, ok := attack.Get(p.Technique); ok {
			v.Matrix = string(t.Matrix)
			v.Tactic = string(t.Tactic())
		}
		for _, sig := range p.Detect.Signals {
			v.Signals = append(v.Signals, sig.Name)
		}
		rep.Packs = append(rep.Packs, v)
	}
	return rep
}

// ReleasePack lifts a pack's quarantine on one address, which is what an
// operator does when the laptop that tripped a pack turns out to be the
// commissioning engineer's. It reports whether there was one to lift.
func (s *Server) ReleasePack(addr netip.Addr) bool { return s.packs.Release(addr) }
