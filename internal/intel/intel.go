// Package intel holds imported threat intelligence: lists of client
// addresses and TLS fingerprints somebody else attributed, with what to
// do about a match.
//
// It is deliberately a different thing from the ban list beside it. A ban
// is earned here: this proxy watched a client do something and decided.
// A list is imported -- a feed of scanner networks, of exit nodes, of
// addresses seen attacking somebody else -- and it says nothing about
// what the client did *here*. That difference is why the two are
// configured separately and why the actions differ: a list whose
// provenance an operator cannot check should usually challenge rather
// than block, since a feed with one wrong line is an outage nobody can
// explain from the logs.
//
// Everything about a list is therefore explicit: where it came from, how
// many entries it holds, when it was last read, and how many requests it
// has matched. A list that cannot be read at load is a load error rather
// than a list that silently matches nothing -- the failure mode that
// makes an imported list worse than none.
package intel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kinds of list.
//
// The first two are about the client -- who is connecting. The rest are about
// what the client asked for, which is a different question and often a more
// useful one: a compromised machine on a network nobody has attributed still
// reaches for a domain somebody has.
const (
	KindCIDR   = "cidr"   // client addresses and networks
	KindJA4    = "ja4"    // TLS client fingerprints
	KindDomain = "domain" // host names, and every name under them
	KindURL    = "url"    // host and path, matched at a path boundary
	KindHash   = "hash"   // MD5, SHA-1 or SHA-256 digests of a payload
)

// Actions a match may take.
const (
	ActionLog       = "log"       // record it and serve the request
	ActionChallenge = "challenge" // make the client prove it is a browser
	ActionBlock     = "block"     // refuse it
)

// MaxEntries bounds one list. A feed larger than this is a feed this
// proxy would hold in memory per generation and match on every request,
// so it is refused with the number rather than loaded halfway.
const MaxEntries = 1 << 20

// Bounds on what one subject may be matched against.
const (
	// maxLabels bounds the suffix walk a domain match does. A name with more
	// labels than this is not a name any feed lists; walking it would be a
	// client choosing how much work the match costs.
	maxLabels = 64
	// maxSegments bounds the path-boundary walk a url match does, for the
	// same reason.
	maxSegments = 64
	// maxName bounds a name or a URL a list may hold, and one offered for
	// matching. 255 is the DNS limit; a URL gets more because a path may be
	// long, and a feed line longer than this is not an indicator.
	maxName = 255
	maxURL  = 2048
)

// List is one imported list.
type List struct {
	Name   string
	Kind   string
	Action string
	// File is where the entries came from, for a file source.
	File string
	// The network sources. Exactly one of File, URL, TAXII and MISP is set;
	// validation refuses a list with none or several, because a list whose
	// source is ambiguous is a list nobody can say the contents of.
	URL   string
	TAXII *TAXIISpec
	MISP  *MISPSpec
	// fetch is the HTTP client for a network source, built once so the
	// connection pool and the TLS session cache survive a refresh.
	fetch *fetcher
	// digest is the SHA-256 of the document the entries came from, which is
	// how a fetch decides whether anything changed. A feed that answers
	// identically has not changed, whatever its headers said.
	digest [32]byte
	// Fetches, Failures and NotModified count what the source has done since
	// start. The three are separate because they mean different things: a
	// failure is something to fix, a 304 is the feed working as intended, and
	// the ratio of the first to the second is whether this list is current.
	Fetches, Failures, NotModified atomic.Uint64
	// Format is how the file is written; see Spec.
	Format string
	// Skipped is what the last read of a structured document could not use:
	// objects and attributes that are not indicators this proxy can match on.
	// Reported rather than hidden -- a bundle of ten thousand objects that
	// yields four entries is either the wrong feed or a feed of things this
	// cannot act on, and an operator should see which.
	Skipped int
	// Hits counts the requests this list matched.
	Hits atomic.Uint64

	// entries, guarded by the Set's lock.
	//
	// nets holds the cidr kind. exact holds every other kind: a ja4
	// fingerprint, a normalised domain, a normalised host-and-path, or a
	// lower-case hex digest. One map serves them all because the lookup is
	// the same -- what differs is how a *subject* is turned into the keys
	// to look up, which is the matcher's job rather than the store's.
	nets  []netip.Prefix
	exact map[string]struct{}
	// depth is how far a match has to walk for this list: the label count of
	// its deepest domain entry, or the segment count of its deepest url one.
	// It comes from the entries rather than from a constant so that the cost
	// of a match is a property of the feed an operator chose and not of the
	// name or path an attacker composed -- see domainCandidates.
	depth int
	// read state, so a reload only re-reads what changed.
	modTime time.Time
	size    int64
	count   int
	read    time.Time
}

// Hit is what a match says: which list, and what it asks for.
type Hit struct {
	List   string
	Action string
	Kind   string
}

// Set is the configured lists, in order. The order is the policy: the
// first list that matches decides, so a narrow allowance cannot be
// written after the broad list it was meant to soften.
type Set struct {
	mu    sync.RWMutex
	lists []*List
	// Matches counts requests that matched any list, Reloads the files
	// re-read since start.
	Matches, Reloads atomic.Uint64
	// The refresh loop, started at most once and stopped at most once.
	startOnce, stopOnce sync.Once
	done                chan struct{}
	refreshing          bool
}

// ListStatus is one list in the status view.
type ListStatus struct {
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Action  string    `json:"action"`
	File    string    `json:"file"`
	Entries int       `json:"entries"`
	Hits    uint64    `json:"hits"`
	Read    time.Time `json:"read"`
	// Format is how the file was read, and Skipped what a structured document
	// held that this list did not take: indicators of other kinds, and objects
	// that are not indicators at all. A bundle of ten thousand objects behind
	// four entries is either the wrong feed or the wrong kind, and the pair of
	// numbers is what says which.
	Format  string `json:"format,omitempty"`
	Skipped int    `json:"skipped,omitempty"`
	// Source is the file, URL, TAXII collection or MISP instance this list
	// came from, in one string an operator can read.
	Source string `json:"source,omitempty"`
	// Fetches, Failures and NotModified are what a network source has done
	// since start. The three are separate because they mean different things:
	// a failure is something to fix, a 304 is the feed working as intended,
	// and a list whose failures are climbing while its fetches are not is a
	// list that has stopped being current while still matching.
	Fetches     uint64 `json:"fetches,omitempty"`
	Failures    uint64 `json:"failures,omitempty"`
	NotModified uint64 `json:"not_modified,omitempty"`
}

// Spec is one list as configured. The package takes its own shape rather
// than the configuration's, so a translator or a test can build a set
// without the config package.
type Spec struct {
	Name, Kind, Action, File string
	// Exactly one of File, URL, TAXII and MISP is the source. A network
	// source shares HTTP for its credential, its trust and its timeout.
	URL   string
	TAXII *TAXIISpec
	MISP  *MISPSpec
	HTTP  *HTTPSpec
	// Format is how the file is written: lines, stix, misp, or auto to decide
	// from the bytes. Empty means auto.
	//
	// Naming it is better than sniffing it. A feed whose format is named fails
	// loudly when its publisher changes shape; a sniffed one quietly starts
	// yielding nothing, which is the failure this package exists to refuse.
	Format string
}

// New reads every list. A file that cannot be read, or an entry that
// cannot be parsed, fails here: an imported list that silently matches
// nothing is worse than no list, because the operator believes it works.
func New(specs []Spec) (*Set, error) {
	s := &Set{}
	for _, sp := range specs {
		l := &List{Name: sp.Name, Kind: sp.Kind, Action: sp.Action,
			File: sp.File, Format: sp.Format, URL: sp.URL, TAXII: sp.TAXII, MISP: sp.MISP}
		if l.network() {
			spec := HTTPSpec{}
			if sp.HTTP != nil {
				spec = *sp.HTTP
			}
			if err := checkInsecure(l.sourceURL(), spec); err != nil {
				return nil, fmt.Errorf("threat_intel list %q: %w", l.Name, err)
			}
			fr, err := newFetcher(spec)
			if err != nil {
				return nil, fmt.Errorf("threat_intel list %q: %w", l.Name, err)
			}
			l.fetch = fr
		}
		if l.Kind == "" {
			l.Kind = KindCIDR
		}
		if l.Action == "" {
			l.Action = ActionLog
		}
		// The first load is where a source that cannot be reached is fatal.
		// At start there is nothing to keep, so a proxy that came up with an
		// empty list it believes is populated is the outcome this package
		// exists to prevent -- and unlike a stale list, this failure is
		// visible when somebody is watching.
		if l.network() {
			ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout(sp.HTTP))
			_, err := s.pull(ctx, l)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("threat_intel list %q: %w", l.Name, err)
			}
		} else if err := s.read(l); err != nil {
			return nil, fmt.Errorf("threat_intel list %q: %w", l.Name, err)
		}
		s.lists = append(s.lists, l)
	}
	return s, nil
}

// MaxDocument bounds a structured feed document. A STIX bundle or a MISP export
// is read whole -- there is no streaming JSON here -- so the bound is on the
// file rather than on the parser's appetite, and a document larger than this is
// refused with the number rather than read into memory to find out.
const MaxDocument = 64 << 20

// network reports whether this list's source is fetched rather than read.
func (l *List) network() bool {
	return l.URL != "" || l.TAXII != nil || l.MISP != nil
}

// sourceURL is the source as a URL, for the messages and for the insecure
// check. Empty for a file.
func (l *List) sourceURL() string {
	switch {
	case l.URL != "":
		return l.URL
	case l.TAXII != nil:
		return l.TAXII.APIRoot
	case l.MISP != nil:
		return l.MISP.BaseURL
	}
	return ""
}

// Source is the source in one string, for the status view.
func (l *List) Source() string {
	switch {
	case l.URL != "":
		return l.URL
	case l.TAXII != nil:
		return "taxii " + strings.TrimRight(l.TAXII.APIRoot, "/") + " collection " + l.TAXII.Collection
	case l.MISP != nil:
		return "misp " + l.MISP.BaseURL
	}
	return l.File
}

// checkInsecure refuses verification-skipping anywhere but the loopback.
//
// A feed fetched without verifying the server is a feed anything on the path can
// write, and what it writes becomes this proxy's block list -- so the setting
// exists for a development instance on 127.0.0.1 and nowhere else. Refused
// rather than warned about: there is no estate where taking a block list from an
// unauthenticated stranger is the intent.
func checkInsecure(rawURL string, spec HTTPSpec) error {
	if !spec.Insecure {
		return nil
	}
	if !spec.AllowInsecure {
		return errors.New("insecure is set without allow_insecure; skipping verification takes two decisions rather than one")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("source url: %w", err)
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	return fmt.Errorf("insecure is set for %s; verification may only be skipped for a loopback address, because a feed nobody authenticated becomes this proxy's block list", host)
}

// fetchDocument gets a network source's document, or reports that it has not
// changed. first says whether this is the load rather than a refresh.
func (l *List) fetchDocument(ctx context.Context) ([]byte, error) {
	switch {
	case l.URL != "":
		return l.fetch.fetchURL(ctx, l.URL)
	case l.TAXII != nil:
		return l.fetch.fetchTAXII(ctx, *l.TAXII)
	case l.MISP != nil:
		return l.fetch.fetchMISP(ctx, *l.MISP)
	}
	return nil, errors.New("no network source")
}

// pull fetches a network source and loads it, reporting whether anything
// changed.
//
// A fetch that fails leaves the entries in force and is counted -- the same rule
// the file path has, and for the same reason: a TAXII server having an afternoon
// must not empty the policy. The one exception is the first load, where there is
// nothing to keep; New treats that as fatal.
func (s *Set) pull(ctx context.Context, l *List) (bool, error) {
	data, err := l.fetchDocument(ctx)
	switch {
	case errors.Is(err, errNotModified):
		l.NotModified.Add(1)
		s.mu.Lock()
		l.read = time.Now()
		s.mu.Unlock()
		return false, nil
	case err != nil:
		l.Failures.Add(1)
		return false, err
	}
	l.Fetches.Add(1)
	sum := digestOf(data)
	s.mu.RLock()
	same := sum == l.digest && l.count > 0
	s.mu.RUnlock()
	if same {
		// Identical bytes. Recording the time still matters: "last read" is
		// what tells an operator the feed is being polled at all.
		s.mu.Lock()
		l.read = time.Now()
		s.mu.Unlock()
		return false, nil
	}
	ent, err := l.entries(bytes.NewReader(data))
	if err != nil {
		l.Failures.Add(1)
		return false, err
	}
	s.mu.Lock()
	l.nets, l.exact, l.count, l.depth, l.Skipped = ent.nets, ent.exact, ent.count, ent.depth, ent.skipped
	l.digest, l.size, l.read = sum, int64(len(data)), time.Now()
	s.mu.Unlock()
	return true, nil
}

// read loads a list's file into it.
func (s *Set) read(l *List) error {
	f, err := os.Open(l.File) //nolint:gosec // a configured path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > MaxDocument {
		return fmt.Errorf("%d bytes; at most %d", info.Size(), MaxDocument)
	}
	ent, err := l.entries(f)
	if err != nil {
		return err
	}
	s.mu.Lock()
	l.nets, l.exact, l.count, l.depth, l.Skipped = ent.nets, ent.exact, ent.count, ent.depth, ent.skipped
	l.modTime, l.size, l.read = info.ModTime(), info.Size(), time.Now()
	s.mu.Unlock()
	return nil
}

// entrySet is what one read produced.
type entrySet struct {
	nets    []netip.Prefix
	exact   map[string]struct{}
	count   int
	depth   int
	skipped int
}

// entries reads a document in whichever format the list is, and keeps the
// indicators of the list's own kind.
//
// A structured document carries several kinds -- a bundle has domains, URLs,
// digests and addresses in it -- and a list has one kind and one action. So a
// list takes the indicators of its kind and counts the rest as skipped. An
// estate that wants to block the domains and only log the digests configures
// two lists over the same file, which is the same shape the package already
// has and says the two policies out loud rather than inferring one.
func (l *List) entries(r io.Reader) (entrySet, error) {
	format := l.Format
	if format == "" {
		format = FormatAuto
	}
	if format == FormatLines {
		return l.entriesFromLines(r)
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxDocument+1))
	if err != nil {
		return entrySet{}, err
	}
	if len(data) > MaxDocument {
		return entrySet{}, fmt.Errorf("more than %d bytes", MaxDocument)
	}
	if format == FormatAuto {
		format = detectFormat(data)
		if format == FormatLines {
			return l.entriesFromLines(bytes.NewReader(data))
		}
	}
	var p *parsed
	switch format {
	case FormatSTIX:
		p, err = parseSTIX(data)
	case FormatMISP:
		p, err = parseMISP(data)
	default:
		return entrySet{}, fmt.Errorf("format %q is not lines, stix, misp or auto", format)
	}
	if err != nil {
		return entrySet{}, err
	}
	return l.entriesFromParsed(p)
}

// entriesFromParsed keeps the indicators of this list's kind out of a parsed
// document, and counts everything else as skipped.
func (l *List) entriesFromParsed(p *parsed) (entrySet, error) {
	kind := l.Kind
	if kind == "" {
		kind = KindCIDR
	}
	mine := p.byKind[kind]
	// Every indicator of another kind is skipped for this list, on top of what
	// the parser itself could not read. Both numbers are the same thing from
	// the operator's side: what was in the document and is not in the list.
	skipped := p.skipped + p.total() - len(mine)
	if len(mine) == 0 {
		return entrySet{}, fmt.Errorf("no %s indicators in the document (it held %d of other kinds, and %d objects could not be read)",
			kind, p.total(), p.skipped)
	}
	if len(mine) > MaxEntries {
		return entrySet{}, fmt.Errorf("more than %d entries", MaxEntries)
	}
	out := entrySet{count: len(mine), skipped: skipped}
	if kind == KindCIDR {
		out.nets = make([]netip.Prefix, 0, len(mine))
		for _, v := range mine {
			pfx, err := parsePrefix(v)
			if err != nil {
				// The parsers check this before adding, so reaching here is a
				// bug rather than a bad feed; say which.
				return entrySet{}, fmt.Errorf("internal: %q from a parsed document is not an address: %w", v, err)
			}
			out.nets = append(out.nets, pfx)
		}
		return out, nil
	}
	out.exact = make(map[string]struct{}, len(mine))
	for _, v := range mine {
		out.exact[v] = struct{}{}
		switch kind {
		case KindDomain:
			if n := labelCount(v); n > out.depth {
				out.depth = n
			}
		case KindURL:
			if n := segmentCount(v); n > out.depth {
				out.depth = n
			}
		}
	}
	// The parsers normalise, so an entry deeper than the walk bound would be a
	// document this cannot match on rather than a line an operator mistyped.
	if out.depth > maxSegments {
		return entrySet{}, fmt.Errorf("an indicator with %d parts; at most %d, because every request would walk that many candidates",
			out.depth, maxSegments)
	}
	return out, nil
}

// entriesFromLines reads the plain form: one indicator per line.
func (l *List) entriesFromLines(r io.Reader) (entrySet, error) {
	var out entrySet
	if l.Kind != KindCIDR && l.Kind != "" {
		out.exact = map[string]struct{}{}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		// A feed is a file somebody else writes, so the comment forms in
		// use are all tolerated; what is not tolerated is an entry that
		// cannot be read.
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") || strings.HasPrefix(text, "//") {
			continue
		}
		// A trailing label or comment on the line is not part of the entry --
		// except for a hash list, where the digest may be the *second* field
		// ("sha256 <digest>") and cutting at the space would keep the
		// algorithm's name instead. hashKey searches the whole line.
		if l.Kind != KindHash {
			if i := strings.IndexAny(text, " \t#"); i > 0 {
				text = strings.TrimSpace(text[:i])
			}
		}
		if out.count++; out.count > MaxEntries {
			return entrySet{}, fmt.Errorf("more than %d entries", MaxEntries)
		}
		switch l.Kind {
		case KindJA4:
			if len(text) > 128 {
				return entrySet{}, fmt.Errorf("line %d: %q is too long for a fingerprint", line, text)
			}
			out.exact[text] = struct{}{}
		case KindDomain:
			key, err := domainKey(text)
			if err != nil {
				return entrySet{}, fmt.Errorf("line %d: %q: %w", line, text, err)
			}
			if n := labelCount(key); n > maxDomainDepth {
				return entrySet{}, fmt.Errorf("line %d: %q: %d labels; at most %d, because every request would walk that many candidates",
					line, text, n, maxDomainDepth)
			} else if n > out.depth {
				out.depth = n
			}
			out.exact[key] = struct{}{}
		case KindURL:
			key, err := urlKey(text)
			if err != nil {
				return entrySet{}, fmt.Errorf("line %d: %q: %w", line, text, err)
			}
			if n := segmentCount(key); n > maxSegments {
				return entrySet{}, fmt.Errorf("line %d: %q: %d path segments; at most %d, because every request would walk that many candidates",
					line, text, n, maxSegments)
			} else if n > out.depth {
				out.depth = n
			}
			out.exact[key] = struct{}{}
		case KindHash:
			key, err := hashKey(text)
			if err != nil {
				return entrySet{}, fmt.Errorf("line %d: %q: %w", line, text, err)
			}
			out.exact[key] = struct{}{}
		default:
			p, err := parsePrefix(text)
			if err != nil {
				return entrySet{}, fmt.Errorf("line %d: %q: %w", line, text, err)
			}
			out.nets = append(out.nets, p)
		}
	}
	if err := sc.Err(); err != nil {
		return entrySet{}, err
	}
	return out, nil
}

// parsePrefix reads an address or a network, the two forms every feed of
// addresses is written in.
func parsePrefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		// Kept as written, host bits and all: Contains compares only the
		// prefix bits, so "10.1.2.3/8" and "10.0.0.0/8" match the same
		// addresses, and feeds are written both ways.
		return netip.ParsePrefix(text)
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, errors.New("not an address or a network")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// A Subject is what one check offers the lists: whatever of it the caller
// knows. A zero field is not matched against, so an HTTP request offers an
// address, a fingerprint, a host and a URL, a DNS question offers a name, and
// an upload offers digests -- each against the lists of the kinds it can
// answer, and never against the others.
//
// It is a struct rather than a list of arguments because the kinds will grow
// again: a caller that does not know about a kind added later passes a zero
// field for it and keeps compiling, which is the difference between adding an
// indicator kind and editing every listener.
type Subject struct {
	// IP is the client's address, for the cidr lists.
	IP netip.Addr
	// JA4 is the client's TLS fingerprint, for the ja4 lists.
	JA4 string
	// Domain is a name the client asked for: an HTTP Host, a DNS question, a
	// CONNECT target, a SNI. For the domain lists.
	Domain string
	// URL is a host and path the client asked for, with or without a scheme.
	// For the url lists.
	URL string
	// Hashes are hex digests of a payload -- an uploaded file, a scanned
	// body. For the hash lists. Any of MD5, SHA-1 and SHA-256.
	Hashes []string
}

// Match reports the first list that covers this subject, in the order the
// lists were configured -- which is the policy: the first list that matches
// decides, so a narrow allowance cannot be written after the broad list it was
// meant to soften.
func (s *Set) Match(sub Subject) (Hit, bool) {
	if s == nil {
		return Hit{}, false
	}
	ip := sub.IP.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.lists {
		if !l.matches(ip, sub) {
			continue
		}
		l.Hits.Add(1)
		s.Matches.Add(1)
		return Hit{List: l.Name, Action: l.Action, Kind: l.Kind}, true
	}
	return Hit{}, false
}

// MatchClient is Match for the callers that know only who is connecting, which
// is every listener kind that has no request to look at.
func (s *Set) MatchClient(ip netip.Addr, ja4 string) (Hit, bool) {
	return s.Match(Subject{IP: ip, JA4: ja4})
}

// matches reports whether one list covers the subject. Called with the Set's
// lock held for reading.
func (l *List) matches(ip netip.Addr, sub Subject) bool {
	switch l.Kind {
	case KindJA4:
		// A client with no fingerprint -- a plaintext listener -- cannot
		// match: an empty line is never an entry, so the empty string is
		// never in the map.
		_, ok := l.exact[sub.JA4]
		return ok
	case KindDomain:
		if sub.Domain == "" {
			return false
		}
		return domainCandidates(sub.Domain, l.depth, func(k string) bool {
			_, ok := l.exact[k]
			return ok
		})
	case KindURL:
		if sub.URL == "" {
			return false
		}
		return urlCandidates(sub.URL, l.depth, func(k string) bool {
			_, ok := l.exact[k]
			return ok
		})
	case KindHash:
		for _, h := range sub.Hashes {
			// Normalised the same way an entry was, so a caller that hands
			// over an upper-case digest still matches.
			k, err := hashKey(h)
			if err != nil {
				continue
			}
			if _, ok := l.exact[k]; ok {
				return true
			}
		}
		return false
	default:
		return ip.IsValid() && covers(l.nets, ip)
	}
}

// covers reports whether any prefix contains the address. The lists are
// held as written rather than as a trie: a feed is tens of thousands of
// prefixes, the scan is linear in that, and a trie is a second structure
// to keep correct for a gain nobody has measured here. The bound on
// entries is what keeps the scan honest.
func covers(nets []netip.Prefix, ip netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// fetchTimeout is the bound on one fetch, defaulted.
func fetchTimeout(spec *HTTPSpec) time.Duration {
	if spec != nil && spec.Timeout > 0 {
		return spec.Timeout
	}
	return DefaultFetchTimeout
}

// Reload re-reads the lists whose file changed and re-fetches the network ones,
// and reports how many changed.
//
// A file that has become unreadable, and a fetch that failed, both keep the
// entries already loaded: a feed being rewritten in place, or a TAXII server
// having an afternoon, must not empty the policy for as long as it takes. The
// failure is returned so the caller can log it and is counted per list, because
// a list that has quietly stopped updating is the failure mode worth alerting
// on -- and it looks exactly like a list that is working.
func (s *Set) Reload() (int, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.RLock()
	lists := make([]*List, len(s.lists))
	copy(lists, s.lists)
	s.mu.RUnlock()
	changed := 0
	var firstErr error
	for _, l := range lists {
		if l.network() {
			ctx, cancel := context.WithTimeout(context.Background(), l.fetch.timeout())
			did, err := s.pull(ctx, l)
			cancel()
			switch {
			case err != nil:
				if firstErr == nil {
					firstErr = fmt.Errorf("threat_intel list %q: %w", l.Name, err)
				}
			case did:
				changed++
				s.Reloads.Add(1)
			}
			continue
		}
		info, err := os.Stat(l.File)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.mu.RLock()
		same := info.ModTime().Equal(l.modTime) && info.Size() == l.size
		s.mu.RUnlock()
		if same {
			continue
		}
		if err := s.read(l); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("threat_intel list %q: %w", l.Name, err)
			}
			continue
		}
		changed++
		s.Reloads.Add(1)
	}
	return changed, firstErr
}

// Status reports every list.
func (s *Set) Status() []ListStatus {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ListStatus, 0, len(s.lists))
	for _, l := range s.lists {
		out = append(out, ListStatus{Name: l.Name, Kind: l.Kind, Action: l.Action,
			File: l.File, Entries: l.count, Hits: l.Hits.Load(), Read: l.read,
			Format: l.Format, Skipped: l.Skipped, Source: l.Source(),
			Fetches: l.Fetches.Load(), Failures: l.Failures.Load(), NotModified: l.NotModified.Load()})
	}
	return out
}

// Len is the number of lists.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.lists)
}

// Refresh re-reads changed files every interval until Stop. A feed is a
// file somebody else's cron job rewrites, so the alternative is an
// operator reloading the proxy to pick up a list that changed on its own
// schedule. onError is called with what a failed re-read said; the
// entries already loaded stay in force.
func (s *Set) Refresh(interval time.Duration, onError func(error)) {
	if s == nil || interval <= 0 || len(s.lists) == 0 {
		return
	}
	s.startOnce.Do(func() {
		s.done = make(chan struct{})
		s.mu.Lock()
		s.refreshing = true
		s.mu.Unlock()
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-s.done:
					return
				case <-t.C:
					if _, err := s.Reload(); err != nil && onError != nil {
						onError(err)
					}
				}
			}
		}()
	})
}

// Refreshing reports whether the refresh loop is running, which is what
// a status view answers "are these lists being watched" with.
func (s *Set) Refreshing() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshing
}

// Stop ends the refresh loop. It is safe to call on a set that never
// started one, and twice.
func (s *Set) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.refreshing = false
		s.mu.Unlock()
		if s.done != nil {
			close(s.done)
		}
	})
}
