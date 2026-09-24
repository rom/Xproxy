package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Response policy zones (RPZ): the file format a DNS threat feed
// actually ships in.
//
// The block list here takes a flat list of names, which is what an
// operator writes by hand. What a feed publishes is a zone file: the
// policy is in the records, so one file says "this name does not exist",
// "this one answers 10.0.0.1" and "this one is an exception" without a
// key per behaviour, and the feed is transferred and diffed by tools
// that already exist. Reading it here means a subscription can be
// dropped in rather than converted every hour by a script somebody
// wrote once.
//
// The subset implemented is the QNAME trigger and the five policy
// actions, which is what a name-based feed uses:
//
//	blocked.example       CNAME .              ; NXDOMAIN
//	*.blocked.example     CNAME .              ; and every subdomain
//	empty.example         CNAME *.             ; NODATA
//	allowed.example       CNAME rpz-passthru.  ; an exception
//	quiet.example         CNAME rpz-drop.      ; no answer at all
//	tcp.example           CNAME rpz-tcp-only.  ; truncated over UDP
//	walled.example        A     10.0.0.1       ; local data
//
// The triggers this does not implement are named in the error a zone
// carrying one produces, because a zone whose rules half apply is a
// policy the operator believes works: rpz-client-ip, rpz-ip,
// rpz-nsdname and rpz-nsip select on the client, on the addresses in an
// answer, and on the name servers of the delegation -- the last two
// needing the resolver to police a path this one forwards. Where an
// answer's addresses are the concern, `answer_policy` screens them
// already, and by range rather than by feed.

// Bounds. A feed of a million names is ordinary; a file that is orders
// past that is a mistake worth an error rather than a resolver that
// stops answering while it reads.
const (
	// MaxRPZRules bounds one zone.
	MaxRPZRules = 2_000_000
	// MaxRPZFile bounds a zone file on disk.
	MaxRPZFile = 256 << 20
	// MaxRPZLine bounds one record.
	MaxRPZLine = 4096
)

// The actions a rule can take. RPZAction is also the override an
// operator sets on a zone, plus RPZZone meaning "the zone's own".
const (
	RPZZoneAction = "zone"
	RPZNXDomain   = "nxdomain"
	RPZNoData     = "nodata"
	RPZPassthru   = "passthru"
	RPZDrop       = "drop"
	RPZTCPOnly    = "tcp_only"
	RPZLocalData  = "local"
	rpzDefaultTTL = 300
	// The three policy targets a rule points at instead of a name.
	rpzPassthruRR  = "rpz-passthru" //nolint:gosec // a record name, not a credential
	rpzDropRR      = "rpz-drop"
	rpzTCPOnlyRR   = "rpz-tcp-only"
	rpzMaxRuleName = 253
)

// RPZSpec is one configured zone.
type RPZSpec struct {
	// Name identifies the zone in logs and in the status view.
	Name string
	// File is the zone file.
	File string
	// Override replaces every rule's own action with one of the action
	// names; empty or "zone" honours the file.
	Override string
	// Origin is the zone's own name, which comes off the front of every
	// rule: a rule written as "evil.example.rpz.local" in a zone whose
	// origin is "rpz.local" matches "evil.example". It is usually in the
	// file, as $ORIGIN or as the SOA's owner; this is for a file that
	// arrived without either, which is what a plain download of a feed
	// sometimes is.
	Origin string
	// IgnoreUnsupported accepts a zone that carries a trigger this
	// resolver does not implement, counting the rules it skipped rather
	// than failing the load. Off by default: a policy that half applies
	// is worse than one that does not load.
	IgnoreUnsupported bool
}

// rpzRule is one compiled rule.
type rpzRule struct {
	// action is one of the action names.
	action string
	// records are the local data of an action of "local", already in the
	// form the answer is built from.
	records []LocalRecord
}

// rpzZone is one compiled zone file.
type rpzZone struct {
	spec RPZSpec
	// exact holds the rules for a name, wild the rules for "*.name"
	// (every subdomain, not the name itself).
	exact map[string]rpzRule
	wild  map[string]rpzRule
	// origin is the zone's own name, stripped from every rule.
	origin string
	// ignored counts rules skipped because their trigger is not
	// implemented here.
	ignored int
	// stamp is the file as it was read.
	size    int64
	modTime time.Time
	// Matches counts the queries this zone decided.
	Matches atomic.Uint64
}

// RPZ is the set of zones in force, in order: the first zone with a rule
// for the name decides, which is what lets a local exception zone sit in
// front of a subscription.
type RPZ struct {
	mu    sync.RWMutex
	zones []*rpzZone

	// Reloads counts the re-reads that changed a zone; Errors the ones
	// that failed and left the previous rules in force.
	Reloads, Errors atomic.Uint64
	// Passthru, Dropped and Answered count what the actions did.
	Matches, Passthru, Dropped, Answered atomic.Uint64

	startOnce, stopOnce sync.Once
	done                chan struct{}
	refreshing          atomic.Bool
}

// RPZHit is what a match decided.
type RPZHit struct {
	// Zone is the zone's name and Rule the name the rule was written
	// for, so a log line says which line of which feed acted.
	Zone, Rule string
	Action     string
	Records    []LocalRecord
}

// NewRPZ reads the zones. A file that cannot be read or parsed fails,
// because a policy zone that silently matches nothing is worse than none
// at all: the operator believes the feed is in force.
func NewRPZ(specs []RPZSpec) (*RPZ, error) {
	if len(specs) == 0 {
		return nil, errors.New("rpz: no zones")
	}
	set := &RPZ{done: make(chan struct{})}
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.Name == "" {
			return nil, errors.New("rpz: a zone needs a name")
		}
		if seen[spec.Name] {
			return nil, fmt.Errorf("rpz: duplicate zone %q", spec.Name)
		}
		seen[spec.Name] = true
		z, err := readRPZ(spec)
		if err != nil {
			return nil, err
		}
		set.zones = append(set.zones, z)
	}
	return set, nil
}

// Match returns the rule in force for a name, if any. The name is lower
// case without a trailing dot, as the server holds it.
func (s *RPZ) Match(qname string) (RPZHit, bool) {
	if s == nil {
		return RPZHit{}, false
	}
	s.mu.RLock()
	zones := s.zones
	s.mu.RUnlock()
	for _, z := range zones {
		if hit, ok := z.match(qname); ok {
			z.Matches.Add(1)
			s.Matches.Add(1)
			switch hit.Action {
			case RPZPassthru:
				s.Passthru.Add(1)
			case RPZDrop:
				s.Dropped.Add(1)
			default:
				s.Answered.Add(1)
			}
			return hit, true
		}
	}
	return RPZHit{}, false
}

// match finds the rule for a name the way a zone lookup does: the name
// itself, then a wildcard on each parent, longest first. A rule written
// without a wildcard covers that name and nothing under it, which is
// what the zone says and what a feed's author relied on -- so
// `good.bank.example CNAME rpz-passthru.` is an exception for that host,
// and `*.bank.example CNAME .` still denies everything else below.
func (z *rpzZone) match(qname string) (RPZHit, bool) {
	if r, ok := z.exact[qname]; ok {
		return z.hit(qname, r), true
	}
	name := qname
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		parent := name[i+1:]
		if r, ok := z.wild[parent]; ok {
			return z.hit("*."+parent, r), true
		}
		name = parent
	}
	return RPZHit{}, false
}

func (z *rpzZone) hit(rule string, r rpzRule) RPZHit {
	action := r.action
	if o := z.spec.Override; o != "" && o != RPZZoneAction {
		action = o
	}
	return RPZHit{Zone: z.spec.Name, Rule: rule, Action: action, Records: r.records}
}

// readRPZ parses one zone file.
func readRPZ(spec RPZSpec) (*rpzZone, error) {
	info, err := os.Stat(spec.File)
	if err != nil {
		return nil, fmt.Errorf("rpz zone %s: %w", spec.Name, err)
	}
	if info.Size() > MaxRPZFile {
		return nil, fmt.Errorf("rpz zone %s: %s is %d bytes, over the %d bound", spec.Name, spec.File, info.Size(), MaxRPZFile)
	}
	data, err := os.ReadFile(spec.File) //nolint:gosec // a path from the configuration
	if err != nil {
		return nil, fmt.Errorf("rpz zone %s: %w", spec.Name, err)
	}
	z := &rpzZone{spec: spec, exact: map[string]rpzRule{}, wild: map[string]rpzRule{},
		size: info.Size(), modTime: info.ModTime()}
	if err := z.parse(string(data)); err != nil {
		return nil, fmt.Errorf("rpz zone %s (%s): %w", spec.Name, spec.File, err)
	}
	if len(z.exact) == 0 && len(z.wild) == 0 {
		return nil, fmt.Errorf("rpz zone %s (%s): no rules; a zone that matches nothing is a policy nobody is applying", spec.Name, spec.File)
	}
	return z, nil
}

// parse reads the master-file subset a policy zone is written in: $TTL
// and $ORIGIN, an SOA and NS records that say whose zone it is, and one
// rule per line. Continuation in parentheses is refused rather than
// half read -- a feed writes one record per line, and a reader that
// guesses at the rest is a reader that applies a rule nobody wrote.
func (z *rpzZone) parse(text string) error {
	ttl := uint32(rpzDefaultTTL)
	origin := strings.TrimSuffix(strings.ToLower(z.spec.Origin), ".")
	z.origin = origin
	last := ""
	for n, raw := range strings.Split(text, "\n") {
		// A record whose owner is absent continues the previous one, and
		// what says so is the leading whitespace: it is read before the
		// line is trimmed, or every continuation would look like a
		// record whose first field is its type.
		stripped := strings.TrimRight(strip(raw), " \t\r")
		continued := stripped != "" && (stripped[0] == ' ' || stripped[0] == '\t')
		line := strings.TrimSpace(stripped)
		if line == "" {
			continue
		}
		if len(line) > MaxRPZLine {
			return fmt.Errorf("line %d: %d bytes, over the %d bound", n+1, len(line), MaxRPZLine)
		}
		if strings.ContainsAny(line, "()") {
			return fmt.Errorf("line %d: a record continued over lines is not read here; write one record per line", n+1)
		}
		if strings.HasPrefix(line, "$") {
			directive, rest, _ := strings.Cut(line, " ")
			value := strings.TrimSpace(rest)
			switch strings.ToUpper(directive) {
			case "$TTL":
				v, err := strconv.ParseUint(strings.Fields(value)[0], 10, 32)
				if err != nil {
					return fmt.Errorf("line %d: $TTL %q: %w", n+1, value, err)
				}
				ttl = uint32(v)
			case "$ORIGIN":
				origin = rpzName(strings.Fields(value)[0], "")
				if origin != "" && !nameOK(origin) {
					return fmt.Errorf("line %d: $ORIGIN %q is not a domain name", n+1, value)
				}
				// The first origin is the zone's own name; a later one
				// only completes the relative owners under it. A master
				// file may move the origin part way down, and the zone
				// is still the zone: taking the moved origin off a rule
				// would make "evil.sub.rpz.local" a rule for "evil"
				// rather than for "evil.sub".
				if z.origin == "" {
					z.origin = origin
				}
			default:
				return fmt.Errorf("line %d: %s is not a directive this reader knows", n+1, directive)
			}
			continue
		}
		owner, fields, err := ownerAndFields(line, last, continued)
		if err != nil {
			return fmt.Errorf("line %d: %w", n+1, err)
		}
		last = owner
		typ, rdata, recordTTL, err := rpzRecord(fields, ttl)
		if err != nil {
			return fmt.Errorf("line %d: %w", n+1, err)
		}
		switch typ {
		case TypeSOA, TypeNS:
			// Whose zone it is, not a rule: the SOA's owner is the zone
			// name, and that name comes off the front of every rule
			// below. A file with neither an $ORIGIN nor an SOA owner of
			// its own -- which a plain download of a feed sometimes is --
			// is read as a list of absolute names, and `origin` in the
			// configuration is how an operator says otherwise.
			if typ == TypeSOA && z.origin == "" && owner != "@" {
				z.origin = rpzName(owner, origin)
			}
			continue
		}
		if owner == "@" {
			// The zone's apex carries the zone's own records, not a
			// rule: a policy record there would match every name.
			continue
		}
		name := rpzName(owner, origin)
		if err := z.addRule(name, typ, rdata, recordTTL); err != nil {
			return fmt.Errorf("line %d: %w", n+1, err)
		}
		if len(z.exact)+len(z.wild) > MaxRPZRules {
			return fmt.Errorf("line %d: over %d rules", n+1, MaxRPZRules)
		}
	}
	return nil
}

// addRule turns one record into a rule, with the zone's own name taken
// off the front: a rule is written as "evil.example.rpz.local", and what
// it matches is "evil.example".
func (z *rpzZone) addRule(owner string, typ uint16, rdata string, ttl uint32) error {
	name := owner
	if z.origin != "" {
		switch {
		case name == z.origin:
			// The zone's apex carries the SOA and the NS records, not a
			// rule; a policy record there would match every name.
			return nil
		case strings.HasSuffix(name, "."+z.origin):
			name = name[:len(name)-len(z.origin)-1]
		}
	}
	wild := false
	if strings.HasPrefix(name, "*.") {
		name, wild = name[2:], true
	}
	if strings.ContainsRune(name, '*') {
		return fmt.Errorf("rule %q: a wildcard is only the first label", owner)
	}
	if name == "" || len(name) > rpzMaxRuleName {
		return fmt.Errorf("rule %q: not a name this resolver can match", owner)
	}
	if err := unsupportedTrigger(name); err != nil {
		if !z.spec.IgnoreUnsupported {
			return err
		}
		z.ignored++
		return nil
	}
	if !nameOK(name) {
		return fmt.Errorf("rule %q: %q is not a domain name", owner, name)
	}
	rule, err := ruleFor(typ, rdata, ttl)
	if err != nil {
		return fmt.Errorf("rule %q: %w", owner, err)
	}
	if wild {
		z.wild[name] = rule
		return nil
	}
	z.exact[name] = rule
	return nil
}

// unsupportedTrigger names a trigger this resolver does not implement,
// rather than storing a rule that would never match.
func unsupportedTrigger(name string) error {
	for _, t := range []string{"rpz-client-ip", "rpz-ip", "rpz-nsdname", "rpz-nsip"} {
		if name == t || strings.HasSuffix(name, "."+t) {
			return fmt.Errorf("rule %q uses the %s trigger, which this resolver does not implement: "+
				"set ignore_unsupported to load the zone without those rules, and see answer_policy for screening where an answer points", name, t)
		}
	}
	return nil
}

// ruleFor reads the action out of the record.
func ruleFor(typ uint16, rdata string, ttl uint32) (rpzRule, error) {
	switch typ {
	case TypeCNAME:
		target := strings.TrimSuffix(strings.ToLower(rdata), ".")
		switch {
		case rdata == ".":
			return rpzRule{action: RPZNXDomain}, nil
		case rdata == "*.":
			return rpzRule{action: RPZNoData}, nil
		case target == rpzPassthruRR:
			return rpzRule{action: RPZPassthru}, nil
		case target == rpzDropRR:
			return rpzRule{action: RPZDrop}, nil
		case target == rpzTCPOnlyRR:
			return rpzRule{action: RPZTCPOnly}, nil
		}
		if !nameOK(target) {
			return rpzRule{}, fmt.Errorf("CNAME %q is neither a policy name nor a domain name", rdata)
		}
		return rpzRule{action: RPZLocalData,
			records: []LocalRecord{{Name: target, Type: TypeCNAME, TTL: ttl, Text: target}}}, nil
	case TypeA, TypeAAAA:
		addr, err := netip.ParseAddr(rdata)
		if err != nil {
			return rpzRule{}, fmt.Errorf("%s %q: %w", TypeName(typ), rdata, err)
		}
		rec := LocalRecord{Type: typ, TTL: ttl, Addr: addr}
		if _, err := rec.Rdata(); err != nil {
			return rpzRule{}, fmt.Errorf("%s %q: %w", TypeName(typ), rdata, err)
		}
		return rpzRule{action: RPZLocalData, records: []LocalRecord{rec}}, nil
	case TypeTXT:
		text := strings.Trim(rdata, `"`)
		rec := LocalRecord{Type: TypeTXT, TTL: ttl, Text: text}
		if _, err := rec.Rdata(); err != nil {
			return rpzRule{}, fmt.Errorf("TXT: %w", err)
		}
		return rpzRule{action: RPZLocalData, records: []LocalRecord{rec}}, nil
	}
	return rpzRule{}, fmt.Errorf("%s is not a record this reader turns into a policy", TypeName(typ))
}

// ownerAndFields splits a record into its owner name and the rest. A
// line beginning with whitespace continues the previous owner, which is
// how a master file writes two records for one name.
func ownerAndFields(line, last string, continued bool) (string, []string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil, errors.New("empty record")
	}
	if continued {
		if last == "" {
			return "", nil, errors.New("a record with no owner, and no previous one to take it from")
		}
		return last, fields, nil
	}
	if len(fields) < 2 {
		return "", nil, fmt.Errorf("%q is not a record", line)
	}
	return fields[0], fields[1:], nil
}

// rpzRecord reads the class, type and rdata of one record. The order of
// a TTL and a class before the type is what master files allow and what
// feeds actually write.
func rpzRecord(fields []string, ttl uint32) (typ uint16, rdata string, recordTTL uint32, err error) {
	recordTTL = ttl
	i := 0
	for ; i < len(fields); i++ {
		f := strings.ToUpper(fields[i])
		if v, convErr := strconv.ParseUint(f, 10, 32); convErr == nil {
			recordTTL = uint32(v)
			continue
		}
		if f == "IN" || f == "CH" || f == "HS" {
			if f != "IN" {
				return 0, "", 0, fmt.Errorf("class %s is not one this resolver serves", f)
			}
			continue
		}
		break
	}
	if i >= len(fields) {
		return 0, "", 0, errors.New("a record with no type")
	}
	switch strings.ToUpper(fields[i]) {
	case "CNAME":
		typ = TypeCNAME
	case "A":
		typ = TypeA
	case "AAAA":
		typ = TypeAAAA
	case "TXT":
		typ = TypeTXT
	case "SOA":
		typ = TypeSOA
	case "NS":
		typ = TypeNS
	default:
		return 0, "", 0, fmt.Errorf("%s is not a record type this reader knows", fields[i])
	}
	rest := strings.Join(fields[i+1:], " ")
	if typ != TypeSOA && typ != TypeNS && strings.TrimSpace(rest) == "" {
		return 0, "", 0, fmt.Errorf("%s with no data", fields[i])
	}
	return typ, strings.TrimSpace(rest), recordTTL, nil
}

// rpzName normalises an owner name: lower case, no trailing dot, and the
// origin appended to a relative one.
func rpzName(owner, origin string) string {
	name := strings.ToLower(strings.TrimSpace(owner))
	switch {
	case name == "@":
		return strings.TrimSuffix(origin, ".")
	case strings.HasSuffix(name, "."):
		return strings.TrimSuffix(name, ".")
	case origin == "":
		return name
	}
	return name + "." + strings.TrimSuffix(origin, ".")
}

// strip removes a comment. A semicolon inside quotes is text, which is
// what a TXT record's own data may hold.
func strip(line string) string {
	quoted := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			quoted = !quoted
		case ';':
			if !quoted {
				return line[:i]
			}
		}
	}
	return line
}

// RPZStatus is the management view of one zone.
type RPZStatus struct {
	Name string `json:"name"`
	File string `json:"file"`
	// Rules is the exact and wildcard rules held, Ignored the ones
	// skipped because their trigger is not implemented here.
	Rules    int    `json:"rules"`
	Ignored  int    `json:"ignored"`
	Override string `json:"override,omitempty"`
	Matches  uint64 `json:"matches"`
	ReadAt   string `json:"read_at"`
}

// Status reports the zones.
func (s *RPZ) Status() []RPZStatus {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RPZStatus, 0, len(s.zones))
	for _, z := range s.zones {
		st := RPZStatus{Name: z.spec.Name, File: z.spec.File,
			Rules: len(z.exact) + len(z.wild), Ignored: z.ignored,
			Matches: z.Matches.Load(), ReadAt: z.modTime.UTC().Format(time.RFC3339)}
		if z.spec.Override != "" && z.spec.Override != RPZZoneAction {
			st.Override = z.spec.Override
		}
		out = append(out, st)
	}
	return out
}

// Zones is the number of zones in force.
func (s *RPZ) Zones() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.zones)
}

// Refreshing reports whether the files are being watched.
func (s *RPZ) Refreshing() bool { return s != nil && s.refreshing.Load() }

// Reload re-reads the zones whose file changed. A zone that cannot be
// read keeps the rules already in force and the error is returned: a
// feed being rewritten in place must not empty the policy for the moment
// that takes.
func (s *RPZ) Reload() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	zones := make([]*rpzZone, len(s.zones))
	copy(zones, s.zones)
	s.mu.RUnlock()
	var firstErr error
	changed := false
	for i, z := range zones {
		info, err := os.Stat(z.spec.File)
		if err != nil {
			s.Errors.Add(1)
			if firstErr == nil {
				firstErr = fmt.Errorf("rpz zone %s: %w", z.spec.Name, err)
			}
			continue
		}
		if info.Size() == z.size && info.ModTime().Equal(z.modTime) {
			continue
		}
		next, err := readRPZ(z.spec)
		if err != nil {
			s.Errors.Add(1)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		next.Matches.Store(z.Matches.Load())
		zones[i] = next
		changed = true
	}
	if changed {
		s.mu.Lock()
		s.zones = zones
		s.mu.Unlock()
		s.Reloads.Add(1)
	}
	return firstErr
}

// Refresh re-reads the files on an interval. onError is called with a
// reload that failed, so the operator hears about a feed that stopped
// parsing while the previous rules stay in force.
func (s *RPZ) Refresh(interval time.Duration, onError func(error)) {
	if s == nil || interval <= 0 {
		return
	}
	s.startOnce.Do(func() {
		s.refreshing.Store(true)
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-s.done:
					return
				case <-t.C:
					if err := s.Reload(); err != nil && onError != nil {
						onError(err)
					}
				}
			}
		}()
	})
}

// Stop ends the refresh loop.
func (s *RPZ) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.done)
		s.refreshing.Store(false)
	})
}

// applyRPZ answers a query a policy zone decided, and reports whether it
// did: a passthru is a decision to answer normally, so the caller carries
// on with the query it was already handling.
func (s *Server) applyRPZ(a *asked, client netip.Addr, proto string, query []byte, qEnd int, h Header,
	q Question, hit RPZHit, tcp bool) ([]byte, bool) {
	if hit.Action == RPZPassthru {
		// An exception, counted so an operator can see the feed being
		// overruled rather than wonder why a name still resolves.
		s.RPZPassthru.Add(1)
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_rpz", a.verified, "listener", s.Name, "zone", hit.Zone,
				"rule", hit.Rule, "action", hit.Action, "name", q.Name, "type", TypeName(q.Type), "proto", proto)
		}
		return nil, false
	}
	if s.hooks.Event != nil {
		s.hooks.Event(client, "dns_rpz", a.verified, "listener", s.Name, "zone", hit.Zone,
			"rule", hit.Rule, "action", hit.Action, "name", q.Name, "type", TypeName(q.Type), "proto", proto)
	}
	if hit.Action == RPZDrop {
		// No answer at all, which is what the rule asks for: a client
		// told nothing learns nothing, and this resolver sends one
		// packet fewer at whatever the query's source really is. It is
		// counted as a drop rather than a refusal, like every other
		// query that gets no answer.
		s.drop(DropRPZ)
		return nil, true
	}
	s.Blocked.Add(1)
	s.refuse("rpz")
	switch hit.Action {
	case RPZTCPOnly:
		if !tcp {
			return s.finish(a, q, "rpz:tcp_only", Truncate(Reply(query, qEnd, h, RcodeNoError), qEnd)), true
		}
		// Over TCP the rule has nothing left to say, so the name is
		// refused rather than answered: a rule that did nothing on the
		// transport it names would be a rule nobody notices.
		return s.finish(a, q, "rpz:tcp_only", Reply(query, qEnd, h, RcodeNXDomain)), true
	case RPZNoData:
		return s.finish(a, q, "rpz:nodata", Reply(query, qEnd, h, RcodeNoError)), true
	case RPZLocalData:
		recs := make([]LocalRecord, 0, len(hit.Records))
		for _, r := range hit.Records {
			if r.Type == q.Type || r.Type == TypeCNAME {
				recs = append(recs, r)
			}
		}
		if len(recs) == 0 {
			// The zone answers this name, but not with what was asked
			// for: NODATA is the honest answer, not the address of
			// another type.
			return s.finish(a, q, "rpz:nodata", Reply(query, qEnd, h, RcodeNoError)), true
		}
		return s.finish(a, q, "rpz:local", s.fit(a, query, qEnd, h, AnswerLocal(query, qEnd, h, q, recs), len(query))), true
	default:
		return s.finish(a, q, "rpz:nxdomain", Reply(query, qEnd, h, RcodeNXDomain)), true
	}
}
