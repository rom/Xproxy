package tftp

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/tftp"
)

// Learning mode for TFTP.
//
// Nobody knows what an estate's TFTP traffic is. The protocol has no
// authentication and no session, so there is nothing to audit and nothing that
// keeps a record: a switch fetches its firmware at three in the morning, a phone
// fetches a configuration every time it reboots, and the server's own log -- if
// it has one -- says a path and an address and nothing about which of them were
// meant to happen. A policy written from the deployment guide refuses the half
// nobody documented, which on this protocol means a switch that does not boot.
//
// What is recorded is where the traffic went and what shape it was, never the
// contents: a TFTP transfer is a configuration file or a firmware image, and a
// learning report is a file that gets pasted into a ticket.
//
// What is recorded and never *proposed* is the amplification: the block size,
// the window and the declared transfer size. Those are what stop a twenty-octet
// request yielding a file to whatever address the datagram claimed to come
// from. They are bounds rather than policy, and a report that proposed the
// largest window it happened to see would be a report that widened the one
// setting learning must not touch. So they appear as observations, under names
// no rule uses, and an engineer who wants them raised raises them on purpose.

const (
	// maxLearnedNames bounds the filenames remembered per subject. A firmware
	// directory holds one image per switch model, and a report listing four
	// hundred of them is a report nobody reads.
	maxLearnedNames = 16
	// maxLearnedExts bounds the extensions. Past a handful there is no pattern
	// to proposeposed, which is itself worth saying.
	maxLearnedExts = 8
)

// learnKey identifies one subject: who, which direction, and which directory.
//
// The directory and not the filename, because `directories` is the line an
// engineer argues about and a subject per file would be a report per file. The
// filenames within it are recorded as a bounded set, which is what a
// `filenames` pattern gets written from.
//
// A path whose class means this relay and the server would read different names
// has no directory: there is nothing to clean about a name whose end two
// parsers disagree on, so the class stands alone as the subject and nothing is
// proposed for it.
type learnKey struct {
	client string
	op     wire.Op
	class  wire.Class
	dir    string
}

// learnObs is what was seen of one subject.
type learnObs struct {
	first, last time.Time
	requests    uint64
	// denied counts the requests the policy refused, or would have refused on a
	// listener learning without enforcement.
	denied uint64
	// serverErrors counts the transfers the server itself ended with an error
	// packet: a file it does not have, or one it will not serve. Those belong
	// out of the policy rather than in it.
	serverErrors uint64
	// completed counts the transfers that finished, which is the number that
	// says a subject is real traffic rather than something probing.
	completed uint64
	// names and exts are what was asked for inside the directory.
	names, exts         map[string]bool
	namesFull, extsFull bool
	modes               map[string]bool
	maxBlockAsked       int
	maxWindowAsked      int
	maxDeclaredSize     int64
	maxBytesMoved       int64
	maxDepth            int
}

type learner = learn.Run[learnKey, learnObs]

// learnConfig is the part of the configuration the learner needs.
type learnConfig struct {
	enabled     bool
	listener    string
	file        string
	interval    time.Duration
	maxSubjects int
}

func newLearner(c *learnConfig) *learner {
	if c == nil || !c.enabled {
		return nil
	}
	return learn.New(learn.Options[learnKey, learnObs]{
		Kind:     "tftp",
		Listener: c.listener,
		Path:     c.file,
		Interval: c.interval,
		Max:      c.maxSubjects,
		Render:   renderLearnedTFTP,
		Less:     learnLessTFTP,
		Clone:    cloneTFTPObs,
	})
}

func learnLessTFTP(a, b learnKey) bool {
	if a.client != b.client {
		return a.client < b.client
	}
	if a.op != b.op {
		return a.op < b.op
	}
	if a.class != b.class {
		return a.class < b.class
	}
	return a.dir < b.dir
}

func cloneTFTPObs(o learnObs) learnObs {
	out := o
	out.names = cloneSet(o.names)
	out.exts = cloneSet(o.exts)
	out.modes = cloneSet(o.modes)
	return out
}

func cloneSet(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// learnSubject is the key one request belongs to.
func learnSubject(client string, op wire.Op, pa wire.Path) learnKey {
	k := learnKey{client: client, op: op, class: pa.Class}
	if pa.Class != wire.ClassPlain {
		// Clean is meaningful only for a class a policy can allow. For the rest
		// the class *is* the finding, and inventing a directory for it would put
		// a path in the report that neither this relay nor the server ever
		// resolved.
		return k
	}
	k.dir = path.Dir(pa.Clean)
	if k.dir == "." || k.dir == "/" {
		// A name at the top of the server's own directory, which is what most
		// estates actually use. The empty string says "no directory" rather
		// than proposing `directories: ["."]`, which matches nothing.
		k.dir = ""
	}
	return k
}

// observeRequest records one request and what the policy said about it.
func (t *server) observeRequest(client string, op wire.Op, pa wire.Path, mode string,
	req *wire.Request, allowed bool, now time.Time) {
	if t.learner == nil {
		return
	}
	key := learnSubject(client, op, pa)
	plain := pa.Class == wire.ClassPlain
	block, window, size := askedFor(req)
	t.learner.Observe(key, func(o *learnObs, first bool) {
		if first {
			o.first = now
			o.names = map[string]bool{}
			o.exts = map[string]bool{}
			o.modes = map[string]bool{}
		}
		o.last = now
		o.requests++
		if !allowed {
			o.denied++
		}
		if mode != "" {
			o.modes[learn.Sanitise(mode)] = true
		}
		if block > o.maxBlockAsked {
			o.maxBlockAsked = block
		}
		if window > o.maxWindowAsked {
			o.maxWindowAsked = window
		}
		if size > o.maxDeclaredSize {
			o.maxDeclaredSize = size
		}
		if !plain {
			return
		}
		if pa.Depth > o.maxDepth {
			o.maxDepth = pa.Depth
		}
		leaf := path.Base(pa.Clean)
		if leaf != "" && leaf != "." && leaf != "/" {
			addBounded(o.names, learn.Sanitise(leaf), maxLearnedNames, &o.namesFull)
			if e := path.Ext(leaf); e != "" {
				addBounded(o.exts, learn.Sanitise(e), maxLearnedExts, &o.extsFull)
			}
		}
	})
}

// addBounded adds a name to a bounded set and says when the set is full, so
// that the report can say a pattern was not generalised rather than proposing
// one from a sample.
func addBounded(m map[string]bool, v string, max int, full *bool) {
	if m[v] {
		return
	}
	if len(m) >= max {
		*full = true
		return
	}
	m[v] = true
}

// askedFor reads the three options that are bounds rather than policy.
func askedFor(req *wire.Request) (block, window int, size int64) {
	if req == nil {
		return 0, 0, 0
	}
	if v, ok := req.Get(wire.OptBlockSize); ok {
		block = atoiOr(v, 0)
	}
	if v, ok := req.Get(wire.OptWindowSize); ok {
		window = atoiOr(v, 0)
	}
	if v, ok := req.Get(wire.OptTransferSize); ok {
		size = int64(atoiOr(v, 0))
	}
	return block, window, size
}

func atoiOr(s string, def int) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return def
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<40 {
			return def
		}
	}
	if len(s) == 0 {
		return def
	}
	return n
}

// observeOutcome records how a transfer ended, against the subject its request
// belonged to.
//
// ObserveExisting rather than Observe: the request is what created the subject,
// and an outcome may not invent one. Nothing else reaches this -- a transfer
// exists only because a request was observed -- but saying so here is what keeps
// it true if that ever changes.
func (t *server) observeOutcome(x *transfer, reason string) {
	if t.learner == nil {
		return
	}
	key := learnSubject(x.ip.String(), x.op, x.path)
	t.learner.ObserveExisting(key, func(o *learnObs) {
		switch reason {
		case "server_error":
			o.serverErrors++
		case "complete":
			o.completed++
		}
		if x.bytes > o.maxBytesMoved {
			o.maxBytesMoved = x.bytes
		}
	})
}

// renderLearnedTFTP writes the report: what was seen, and a rule set that
// permits exactly that.
func renderLearnedTFTP(listener string, subjects []learn.Subject[learnKey, learnObs], st learn.Stats) string {
	var b strings.Builder
	b.WriteString(learn.Header("TFTP", listener, st, time.Now()))
	b.WriteString("#\n")
	b.WriteString("# A subject is one client, one direction and one directory, because\n")
	b.WriteString("# `directories` is the line an engineer argues about and a subject per file\n")
	b.WriteString("# would be a report per file. The filenames inside it are listed so that a\n")
	b.WriteString("# `filenames` pattern can be written from what is actually there.\n")
	b.WriteString("#\n")
	b.WriteString("# Read three things before the proposal. denied_by_policy is what the current\n")
	b.WriteString("# policy refused, or would have. server_errors is what the *server* refused --\n")
	b.WriteString("# a file it does not have -- and a subject with nothing but those is a client\n")
	b.WriteString("# asking for something that does not exist, so no rule is proposed for it. And\n")
	b.WriteString("# path_class says the name was not an ordinary relative path: those are\n")
	b.WriteString("# recorded and never proposed, because a class this relay and the server read\n")
	b.WriteString("# differently is not something to write a rule about.\n")
	b.WriteString("#\n")
	b.WriteString("# The block size, the window and the declared size are observations only. They\n")
	b.WriteString("# are this protocol's amplification factor, not policy, so no rule below sets\n")
	b.WriteString("# max_block_size, max_window_size or max_transfer_bytes: a request past the\n")
	b.WriteString("# bound is lowered to it and still transfers. Raising one is a decision.\n")
	b.WriteString("#\n")
	b.WriteString("# No file contents are here. A TFTP transfer is a configuration or a firmware\n")
	b.WriteString("# image, and a learning report is a file that gets pasted into a ticket.\n\n")

	b.WriteString("observed:\n")
	if len(subjects) == 0 {
		b.WriteString("  []\n")
	}
	for _, s := range subjects {
		k, o := s.Key, s.Obs
		fmt.Fprintf(&b, "  - client: %s\n", learn.Sanitise(k.client))
		fmt.Fprintf(&b, "    operation: %s\n", k.op)
		if k.class != wire.ClassPlain {
			fmt.Fprintf(&b, "    path_class: %s  # not an ordinary path; no rule is proposed\n", k.class)
		}
		if k.dir != "" {
			fmt.Fprintf(&b, "    directory: %s\n", learn.Sanitise(k.dir))
		} else if k.class == wire.ClassPlain {
			b.WriteString("    directory: \"\"  # the top of the server's own directory\n")
		}
		fmt.Fprintf(&b, "    requests: %d\n", o.requests)
		if o.completed > 0 {
			fmt.Fprintf(&b, "    completed: %d\n", o.completed)
		}
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		if o.serverErrors > 0 {
			fmt.Fprintf(&b, "    server_errors: %d  # the server itself said no\n", o.serverErrors)
		}
		if names := sortedSet(o.names); len(names) > 0 {
			fmt.Fprintf(&b, "    filenames_seen: [%s]\n", quoteList(names))
			if o.namesFull {
				fmt.Fprintf(&b, "    filenames_truncated: true  # more than %d distinct names\n", maxLearnedNames)
			}
		}
		if exts := sortedSet(o.exts); len(exts) > 0 {
			fmt.Fprintf(&b, "    extensions_seen: [%s]\n", quoteList(exts))
		}
		if modes := sortedSet(o.modes); len(modes) > 0 {
			fmt.Fprintf(&b, "    modes: [%s]\n", strings.Join(modes, ", "))
		}
		if o.maxDepth > 0 {
			fmt.Fprintf(&b, "    max_depth_seen: %d\n", o.maxDepth)
		}
		// The amplification numbers, under names no rule uses.
		if o.maxBlockAsked > 0 {
			fmt.Fprintf(&b, "    block_size_asked: %d\n", o.maxBlockAsked)
		}
		if o.maxWindowAsked > 0 {
			fmt.Fprintf(&b, "    window_asked: %d\n", o.maxWindowAsked)
		}
		if o.maxDeclaredSize > 0 {
			fmt.Fprintf(&b, "    declared_size: %d\n", o.maxDeclaredSize)
		}
		if o.maxBytesMoved > 0 {
			fmt.Fprintf(&b, "    bytes_moved: %d\n", o.maxBytesMoved)
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}

	b.WriteString("\n# A rule set that permits what was seen, and nothing else.\n")
	b.WriteString("rules:\n")
	proposeTFTPRules(&b, subjects)
	return b.String()
}

// proposeTFTPRules folds the subjects into one rule per client and direction.
func proposeTFTPRules(b *strings.Builder, subjects []learn.Subject[learnKey, learnObs]) {
	type groupKey struct {
		client string
		op     wire.Op
	}
	type group struct {
		dirs     map[string]bool
		exts     map[string]bool
		modes    map[string]bool
		root     bool
		vague    bool
		maxDepth int
	}
	var order []groupKey
	groups := map[groupKey]*group{}
	for _, s := range subjects {
		if s.Key.class != wire.ClassPlain {
			// A name two parsers would read differently. Recorded above and
			// never proposed: a rule about a name the server will not see is
			// not a rule.
			continue
		}
		// A subject the server refused every time is a client asking for
		// something that is not there. Permitting it would permit a thing that
		// cannot happen, and an engineer reading the rule would think it could.
		if s.Obs.requests > 0 && s.Obs.serverErrors >= s.Obs.requests {
			continue
		}
		gk := groupKey{client: s.Key.client, op: s.Key.op}
		g, ok := groups[gk]
		if !ok {
			g = &group{dirs: map[string]bool{}, exts: map[string]bool{}, modes: map[string]bool{}}
			groups[gk] = g
			order = append(order, gk)
		}
		if s.Key.dir == "" {
			g.root = true
		} else {
			g.dirs[s.Key.dir] = true
		}
		for e := range s.Obs.exts {
			g.exts[e] = true
		}
		for m := range s.Obs.modes {
			g.modes[m] = true
		}
		// A subject whose extensions outran the bound, or that used none at
		// all, cannot be generalised into a pattern from what was recorded.
		//
		// The *name* bound does not count here, deliberately. Every name's
		// extension is recorded whether or not the name itself was, so four
		// hundred images all ending .bin leave a set of one -- and
		// `firmware/*.bin` covers the ones that were dropped as well. It is the
		// extension set outrunning its bound that means the sample is not the
		// population.
		if s.Obs.extsFull || len(s.Obs.exts) == 0 {
			g.vague = true
		}
		if s.Obs.maxDepth > g.maxDepth {
			g.maxDepth = s.Obs.maxDepth
		}
	}
	if len(order) == 0 {
		b.WriteString("  []\n")
		return
	}
	for i, gk := range order {
		g := groups[gk]
		fmt.Fprintf(b, "  - name: learned-%d-%s\n", i+1, gk.op)
		b.WriteString("    action: allow\n")
		fmt.Fprintf(b, "    clients: [%s/32]\n", learn.Sanitise(gk.client))
		fmt.Fprintf(b, "    operations: [%s]\n", gk.op)
		if dirs := sortedSet(g.dirs); len(dirs) > 0 {
			fmt.Fprintf(b, "    directories: [%s]\n", quoteList(dirs))
		}
		if g.root {
			b.WriteString("    # Names at the top of the server's own directory were asked for too,\n")
			b.WriteString("    # so `directories` above would refuse them. Either move those files\n")
			b.WriteString("    # into a directory or leave `directories` out of this rule.\n")
		}
		if modes := sortedSet(g.modes); len(modes) > 0 {
			fmt.Fprintf(b, "    modes: [%s]\n", strings.Join(modes, ", "))
		}
		writePatterns(b, g.dirs, g.exts, g.root, g.vague)
	}
}

// writePatterns proposes `filenames` from the directories and extensions seen,
// and refuses to when what was seen does not generalise.
//
// The refusal is the point. The only pattern that always fits is `*`, and a
// proposal that fell back to it would have written a rule permitting every file
// on the server -- while looking like it had been derived from the traffic.
func writePatterns(b *strings.Builder, dirs, exts map[string]bool, root, vague bool) {
	if vague || len(exts) == 0 {
		b.WriteString("    # No `filenames` pattern is proposed: the names seen do not share a\n")
		b.WriteString("    # small set of extensions, so any pattern covering them would be `*`,\n")
		b.WriteString("    # which permits every file on the server. Read filenames_seen above\n")
		b.WriteString("    # and write the pattern by hand.\n")
		return
	}
	pats := make([]string, 0, len(dirs)*len(exts))
	es := sortedSet(exts)
	for _, d := range sortedSet(dirs) {
		for _, e := range es {
			pats = append(pats, d+"/*"+e)
		}
	}
	if root {
		for _, e := range es {
			pats = append(pats, "*"+e)
		}
	}
	if len(pats) == 0 {
		return
	}
	sort.Strings(pats)
	fmt.Fprintf(b, "    filenames: [%s]\n", quoteList(pats))
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func quoteList(ss []string) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return strings.Join(out, ", ")
}
