package iec104

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// Redundancy groups, from edition 2 of the standard, and the thing a relay
// can do about them that the equipment cannot.
//
// A control centre does not reach a substation over one TCP connection. It
// opens several -- different routers, different bearers, sometimes
// different buildings -- and edition 2 calls that set a redundancy group.
// Exactly one connection in a group carries data at a time: the
// controlling station sends STARTDT on the one it wants and that
// connection is *active*, while the others stay connected, exchange
// TESTFR, and carry nothing. When the active path fails, the controlling
// station sends STARTDT on a standby connection and the group has failed
// over.
//
// Two things follow that matter here, and they pull in opposite
// directions.
//
// The first is a control. Without a group, a second connection from the
// control centre's own network is just another client, and an injected
// command on it is decided exactly like one on the first. With a group,
// only the connection holding data transfer may send anything at all: a
// frame from a standby connection is refused before it reaches the
// station, and taking data transfer away from a live connection is a
// failover, which is logged and can be refused outright.
//
// The second is a concession, and it is the reason the group has to be
// declared rather than inferred. Select-before-operate is enforced by
// remembering a selection, and a selection that belongs to a connection
// dies with it -- so a failover between the select and the execute turns a
// legitimate two-step command into a refusal, and a control room that
// meets that during an outage learns to turn require_select off. Carrying
// the selection across the group fixes that by trusting the group's own
// statement that these connections are one controlling station. What keeps
// that from being a hole is the first point: the selection can only be
// consumed by whichever connection currently holds data transfer, so an
// intruder inside the group's client networks has to win a STARTDT as
// well, and that is a logged failover rather than a quiet execute.

// MaxRedundancyConnections bounds the connections one group may hold. A
// redundancy group is two or three paths, occasionally four; a number well
// past that is a client list that has caught something it should not.
const MaxRedundancyConnections = 8

// group is one redundancy group: the connections declared to be one
// controlling station, and which of them holds data transfer.
type group struct {
	name     string
	clients  []netip.Prefix
	max      int
	takeover string
	carry    bool

	mu      sync.Mutex
	members map[uint64]netip.Addr
	// active is the session holding data transfer, or 0 for none, with the
	// address it came from for the log.
	active   uint64
	activeIP netip.Addr
	// failovers counts the times data transfer moved from one live
	// connection to another, and refused the times a takeover was refused
	// because another connection had it. Both are what an operator looks
	// at after an incident: a group that fails over every few minutes is a
	// group whose paths are flapping, or one somebody is fighting over.
	failovers, refused, crowded uint64
}

// groups is the listener's redundancy configuration.
type groups struct {
	list []*group
}

// compileRedundancy builds the groups. Everything that can be wrong about
// one is wrong here, at load: a group is an assertion that a set of
// addresses is one controlling station, and a wrong one is an assertion
// that two control centres are the same peer.
func compileRedundancy(c *config.IEC104Redundancy) (*groups, error) {
	if c == nil || len(c.Groups) == 0 {
		return nil, nil
	}
	g := &groups{}
	seen := map[string]bool{}
	for i := range c.Groups {
		in := &c.Groups[i]
		where := "redundancy.groups." + in.Name
		if in.Name == "" {
			return nil, fmt.Errorf("redundancy.groups[%d].name: required", i)
		}
		if seen[in.Name] {
			return nil, fmt.Errorf("redundancy.groups: duplicate name %q", in.Name)
		}
		seen[in.Name] = true
		if len(in.Clients) == 0 {
			// The client list *is* the group's identity: it is what says
			// which connections are one controlling station. A group
			// without one would claim every client on the listener is the
			// same peer, which is the opposite of a control.
			return nil, fmt.Errorf("%s.clients: required; the client list is what says which connections are one controlling station", where)
		}
		one := &group{name: in.Name, max: in.MaxConnections, takeover: in.Takeover,
			members: map[uint64]netip.Addr{}}
		var err error
		if one.clients, err = prefixes(where+".clients", in.Clients); err != nil {
			return nil, err
		}
		if one.max == 0 {
			one.max = 4
		}
		if one.max < 1 || one.max > MaxRedundancyConnections {
			return nil, fmt.Errorf("%s.max_connections: must be between 1 and %d",
				where, MaxRedundancyConnections)
		}
		switch one.takeover {
		case "":
			one.takeover = "switch"
		case "switch", "refuse":
		default:
			return nil, fmt.Errorf("%s.takeover: must be switch or refuse", where)
		}
		one.carry = in.CarrySelects == nil || *in.CarrySelects
		g.list = append(g.list, one)
	}
	return g, nil
}

// of is the group a client address belongs to, or nil.
//
// First match wins, and overlapping client lists are a configuration
// validation warns about: a connection in two groups would be two
// controlling stations at once.
func (g *groups) of(ip netip.Addr) *group {
	if g == nil {
		return nil
	}
	for _, one := range g.list {
		if netutil.Contains(one.clients, ip) {
			return one
		}
	}
	return nil
}

// Status is each group's name, how many connections it holds, whether one
// of them has data transfer, and the counts.
func (g *groups) Status() []GroupStatus {
	if g == nil {
		return nil
	}
	out := make([]GroupStatus, 0, len(g.list))
	for _, one := range g.list {
		one.mu.Lock()
		s := GroupStatus{Name: one.name, Members: len(one.members),
			Active: one.active != 0, Failovers: one.failovers,
			Refused: one.refused, Crowded: one.crowded}
		if one.active != 0 {
			s.ActiveClient = one.activeIP.String()
		}
		one.mu.Unlock()
		out = append(out, s)
	}
	return out
}

// GroupStatus is one group, for the status view.
type GroupStatus struct {
	Name         string `json:"name"`
	Members      int    `json:"members"`
	Active       bool   `json:"active"`
	ActiveClient string `json:"active_client,omitempty"`
	Failovers    uint64 `json:"failovers"`
	Refused      uint64 `json:"refused_takeovers"`
	Crowded      uint64 `json:"refused_connections"`
}

// join adds a connection to the group, and says whether the group had room
// for it. A group that is full is a group whose paths have not been closed
// or one that has caught a client it should not have, and either way a
// further connection is refused rather than admitted into a set the
// operator said was three paths.
func (g *group) join(session uint64, ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.members) >= g.max {
		g.crowded++
		return false
	}
	g.members[session] = ip
	return true
}

// leave removes a connection and says whether the group is now empty.
//
// Empty matters because it is when the group's carried selections are
// dropped. A selection outliving one connection is the point of the group;
// one outliving the whole control centre's association is a selection
// nobody is waiting on, and its expiry would otherwise be the only bound.
func (g *group) leave(session uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.members, session)
	if g.active == session {
		g.active, g.activeIP = 0, netip.Addr{}
	}
	return len(g.members) == 0
}

// start takes data transfer for this connection. It returns the address
// that held it, whether this is a failover from a live connection, and
// whether the takeover is permitted at all.
func (g *group) start(session uint64, ip netip.Addr) (netip.Addr, bool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	prev, prevIP := g.active, g.activeIP
	if prev == session {
		// A second STARTDT on the connection that already has it. The
		// standard allows it and it means nothing happened.
		return netip.Addr{}, false, true
	}
	if prev != 0 && g.takeover == "refuse" {
		g.refused++
		return prevIP, false, false
	}
	g.active, g.activeIP = session, ip
	if prev != 0 {
		g.failovers++
		return prevIP, true, true
	}
	return netip.Addr{}, false, true
}

// stop releases data transfer if this connection holds it. A STOPDT from a
// standby connection releases nothing, which is what it means.
func (g *group) stop(session uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != session {
		return false
	}
	g.active, g.activeIP = 0, netip.Addr{}
	return true
}

// holds says whether this connection is the group's active one.
func (g *group) holds(session uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active == session
}

// Active says whether any connection in the group holds data transfer, for
// the gauge.
func (g *groups) Active() int {
	if g == nil {
		return 0
	}
	var n int
	for _, one := range g.list {
		one.mu.Lock()
		if one.active != 0 {
			n++
		}
		one.mu.Unlock()
	}
	return n
}
