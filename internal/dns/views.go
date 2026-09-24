package dns

import (
	"net/netip"

	"github.com/rom/xproxy/internal/netutil"
)

// Split horizon: a different answer for the same name, by who asked.
//
// One name with two answers is an ordinary requirement rather than a
// trick. `app.example.com` is a private address from inside the estate and
// a public one from outside; a laboratory network resolves a name to the
// test system while everybody else reaches production; a guest network is
// held to a stricter block list than the staff network. Without views, the
// answer is two resolvers on two addresses and a routing decision
// somewhere else.
//
// A view selects the things this resolver decides *before* it asks
// anything: the records it answers itself, and the names it refuses. That
// is deliberate, and it is why a view has no upstream of its own. Two
// views with different upstreams would answer the same question
// differently from the same cache, and a cache keyed per view is a
// different resolver with a different memory -- which is a second
// listener, and says so in the configuration instead of hiding in a view.
type View struct {
	// Name identifies the view in logs and the status view.
	Name string
	// Clients are the networks this view serves. The first view whose
	// networks contain the client wins, so order is the policy.
	Clients []netip.Prefix
	// Local replaces the listener's own record set while this view is
	// selected; nil keeps it.
	Local *LocalRecords
	// Block replaces the listener's block list; nil keeps it.
	Block *BlockList
	// Action replaces block_action ("nxdomain", "refuse", "sinkhole");
	// empty keeps the listener's.
	Action string
	// Sinkhole4 and Sinkhole6 replace the sinkhole addresses of this
	// view's own action; nil keeps the listener's.
	Sinkhole4, Sinkhole6 []byte
}

// viewFor is the first view whose networks contain the client, or nil.
func (p *Policy) viewFor(client netip.Addr) *View {
	for _, v := range p.Views {
		if netutil.Contains(v.Clients, client) {
			return v
		}
	}
	return nil
}

// answers is the record set, block list and block action in force for one
// query: the view's where it has them, the listener's otherwise. It is one
// function so that a view can never half-apply -- a block list from the
// view with the action from the listener is a configuration nobody wrote.
type answers struct {
	view       string
	local      *LocalRecords
	block      *BlockList
	action     string
	sinkhole4  []byte
	sinkhole6  []byte
	sinkholeIP uint32
}

func (p *Policy) answersFor(v *View) answers {
	a := answers{local: p.Local, block: p.Block, action: p.BlockAction,
		sinkhole4: p.Sinkhole4, sinkhole6: p.Sinkhole6, sinkholeIP: p.SinkholeTTL}
	if v == nil {
		return a
	}
	a.view = v.Name
	if v.Local != nil {
		a.local = v.Local
	}
	if v.Block != nil {
		a.block = v.Block
	}
	if v.Action != "" {
		a.action = v.Action
		// The addresses belong to the action: a view that sinkholes with
		// the listener's addresses is the common case, and one that names
		// its own replaces them.
		if v.Sinkhole4 != nil {
			a.sinkhole4 = v.Sinkhole4
		}
		if v.Sinkhole6 != nil {
			a.sinkhole6 = v.Sinkhole6
		}
	}
	return a
}

// ViewNames lists the views in order, for the status view.
func (p *Policy) ViewNames() []string {
	if len(p.Views) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.Views))
	for _, v := range p.Views {
		out = append(out, v.Name)
	}
	return out
}
