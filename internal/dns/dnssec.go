package dns

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // DS digest type 1 and NSEC3 hashing are SHA-1 by specification
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rom/xproxy/internal/netutil"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result of validating one response.
type Result int

// Validation results (RFC 4035 section 4.3).
const (
	Indeterminate Result = iota // nothing to say: not a NOERROR/NXDOMAIN answer
	Insecure                    // provably outside any signed zone we can reach
	Secure                      // every RRset verified up to a trust anchor
	Bogus                       // signed data that does not verify, or a missing proof
)

func (r Result) String() string {
	switch r {
	case Insecure:
		return "insecure"
	case Secure:
		return "secure"
	case Bogus:
		return "bogus"
	}
	return "indeterminate"
}

// TrustAnchor is a DS record for the root (or another zone): key tag,
// algorithm, digest type and digest.
type TrustAnchor struct {
	Zone       string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// RootAnchors are the IANA root key signing keys (KSK-2017 and
// KSK-2024) as DS records; they are used unless the configuration
// supplies its own.
var RootAnchors = []string{
	". 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	". 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// ParseTrustAnchor reads "zone keytag algorithm digesttype digest" (the
// DS presentation format, with or without "IN DS").
func ParseTrustAnchor(line string) (TrustAnchor, error) {
	f := strings.Fields(line)
	if len(f) >= 6 && strings.EqualFold(f[1], "IN") && strings.EqualFold(f[2], "DS") {
		f = append([]string{f[0]}, f[3:]...)
	}
	if len(f) >= 5 && strings.EqualFold(f[1], "DS") {
		f = append([]string{f[0]}, f[2:]...)
	}
	if len(f) < 5 {
		return TrustAnchor{}, fmt.Errorf("trust anchor %q: want zone keytag algorithm digesttype digest", line)
	}
	tag, err1 := strconv.ParseUint(f[1], 10, 16)
	alg, err2 := strconv.ParseUint(f[2], 10, 8)
	dt, err3 := strconv.ParseUint(f[3], 10, 8)
	digest, err4 := hex.DecodeString(strings.Join(f[4:], ""))
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(digest) == 0 {
		return TrustAnchor{}, fmt.Errorf("trust anchor %q: bad field", line)
	}
	zone := netutil.ASCIILower(strings.TrimSuffix(f[0], "."))
	return TrustAnchor{Zone: zone, KeyTag: uint16(tag), Algorithm: uint8(alg), DigestType: uint8(dt), Digest: digest}, nil
}

// Validator verifies DNSSEC chains for the answers a listener forwards.
// It asks the same upstream resolvers for DNSKEY and DS records, keeps a
// bounded cache of validated (or proven insecure) zones, and bounds the
// work per answer.
type Validator struct {
	resolver *Resolver
	anchors  map[string][]TrustAnchor
	now      func() time.Time
	// MaxLookups bounds DNSKEY and DS queries per validation.
	MaxLookups int
	// Skew is the clock tolerance on signature validity.
	Skew time.Duration

	mu    sync.Mutex
	zones map[string]*zoneState
	cap   int

	secure, insecure, bogus, indeterminate, lookups atomic.Uint64
}

// zoneState is what the validator knows about one zone.
type zoneState struct {
	keys     []dnskey // trusted zone keys (empty when insecure)
	insecure bool
	// inside marks a name the parent proved is not a zone cut: it lives
	// inside the parent zone (keys are the parent's) and can never be an
	// RRSIG signer.
	inside  bool
	expires time.Time
}

type dnskey struct {
	flags uint16
	alg   uint8
	tag   uint16
	pub   []byte
	owner string
	rdata []byte
}

// NewValidator builds a validator over resolver with the given anchors
// (RootAnchors when nil).
func NewValidator(resolver *Resolver, anchors []TrustAnchor) *Validator {
	v := &Validator{resolver: resolver, anchors: map[string][]TrustAnchor{}, now: time.Now, MaxLookups: 48, Skew: 5 * time.Minute,
		zones: map[string]*zoneState{}, cap: 10000}
	if len(anchors) == 0 {
		for _, l := range RootAnchors {
			a, _ := ParseTrustAnchor(l)
			anchors = append(anchors, a)
		}
	}
	for _, a := range anchors {
		v.anchors[a.Zone] = append(v.anchors[a.Zone], a)
	}
	return v
}

// Status returns counters.
func (v *Validator) Status() DNSSECStatus {
	if v == nil {
		return DNSSECStatus{}
	}
	v.mu.Lock()
	n := len(v.zones)
	v.mu.Unlock()
	return DNSSECStatus{Enabled: true, Secure: v.secure.Load(), Insecure: v.insecure.Load(), Bogus: v.bogus.Load(),
		Indeterminate: v.indeterminate.Load(), KeyCache: n, Lookups: v.lookups.Load()}
}

// ---- entry point -----------------------------------------------------------

// Validate checks resp for the question in query. It returns the result
// and the response to send: with AD set when secure and requested,
// SERVFAIL when bogus (unless the client set CD), otherwise resp.
func (v *Validator) Validate(ctx context.Context, query []byte, qEnd int, qh Header, resp []byte) (Result, []byte) {
	m, err := ParseMessage(resp)
	if err != nil {
		v.indeterminate.Add(1)
		return Indeterminate, resp
	}
	res := v.validate(ctx, m)
	switch res {
	case Secure:
		v.secure.Add(1)
	case Insecure:
		v.insecure.Add(1)
	case Bogus:
		v.bogus.Add(1)
	default:
		v.indeterminate.Add(1)
	}
	if res == Bogus && qh.Flags&flagCD == 0 {
		return res, Reply(query, qEnd, qh, RcodeServFail)
	}
	out := append([]byte(nil), resp...)
	flags := binary.BigEndian.Uint16(out[2:])
	flags &^= flagAD
	if res == Secure {
		flags |= flagAD
	}
	binary.BigEndian.PutUint16(out[2:], flags)
	return res, out
}

type work struct {
	ctx     context.Context
	lookups int
}

func (v *Validator) validate(ctx context.Context, m *Message) Result {
	rcode := m.Header.Rcode()
	if rcode != RcodeNoError && rcode != RcodeNXDomain {
		return Indeterminate
	}
	w := &work{ctx: ctx}
	q := m.Question
	answer := groupRRsets(m.Answer)
	authority := groupRRsets(m.Authority)
	// Positive answer: every RRset must verify, and the answer must hold
	// data for the question itself (the name and type asked, or a CNAME
	// or DNAME chain leading from it): signed records of some other name
	// prove nothing about this one.
	if len(answer) > 0 && rcode == RcodeNoError {
		if !answersQuestion(answer, q) {
			return Bogus
		}
		worst := Secure
		for _, set := range answer {
			if set.Type == TypeRRSIG || len(set.RRs) == 0 {
				continue
			}
			r := v.verifyRRset(w, set, authority)
			if r == Bogus {
				return Bogus
			}
			if r == Insecure {
				worst = Insecure
			}
		}
		return worst
	}
	// Negative answer: SOA and denial records in the authority section.
	var soa *RRset
	var nsecs, nsec3s []*RRset
	for _, set := range authority {
		switch set.Type {
		case TypeSOA:
			soa = set
		case TypeNSEC:
			nsecs = append(nsecs, set)
		case TypeNSEC3:
			nsec3s = append(nsec3s, set)
		}
	}
	if soa == nil {
		// No SOA: an unsigned or referral style answer; decide by the
		// security of the name.
		return v.zoneSecurityOf(w, q.Name)
	}
	if len(soa.Sigs) == 0 && len(nsecs) == 0 && len(nsec3s) == 0 {
		return v.zoneSecurityOf(w, q.Name)
	}
	zone := soa.Name
	// The denial must come from the zone the name lives in: a signed SOA
	// and NSEC records of some unrelated zone would otherwise "prove" any
	// name absent.
	if !isSubdomain(q.Name, zone) {
		return Bogus
	}
	if r := v.verifyRRset(w, soa, nil); r != Secure {
		return r
	}
	for _, set := range nsecs {
		if r := v.verifyRRset(w, set, nil); r != Secure {
			return Bogus
		}
	}
	for _, set := range nsec3s {
		if r := v.verifyRRset(w, set, nil); r != Secure {
			return Bogus
		}
	}
	switch {
	case len(nsecs) > 0:
		if rcode == RcodeNXDomain {
			if nsecNameError(nsecs, q.Name, zone) {
				return Secure
			}
		} else if nsecNoData(nsecs, q.Name, q.Type, zone) {
			return Secure
		}
	case len(nsec3s) > 0:
		switch nsec3Denial(nsec3s, q.Name, q.Type, zone, rcode == RcodeNXDomain) {
		case Secure:
			return Secure
		case Insecure:
			return Insecure
		}
	default:
		// A signed SOA without denial records: the zone is signed but
		// the answer lacks its proof.
		return Bogus
	}
	return Bogus
}

// verifyRRset checks an RRset against its signatures and the signer's
// trusted keys. A wildcard expansion needs a denial proof for the query
// name from authority.
func (v *Validator) verifyRRset(w *work, set *RRset, authority []*RRset) Result {
	if len(set.Sigs) == 0 {
		return v.zoneSecurityOf(w, set.Name)
	}
	var lastErr error
	for _, sig := range set.Sigs {
		s, err := parseRRSIG(sig.Data)
		if err != nil {
			lastErr = err
			continue
		}
		if !isSubdomain(set.Name, s.signer) {
			lastErr = errors.New("signer is not an ancestor of the owner")
			continue
		}
		st := v.zoneKeys(w, s.signer)
		if st == nil || st.inside {
			return Bogus // no chain to the signer, or the signer is not a zone apex
		}
		if st.insecure {
			return Insecure
		}
		if err := v.checkSignature(set, s, st.keys); err != nil {
			lastErr = err
			continue
		}
		// Wildcard expansion: the query name itself must be proven absent.
		if int(s.labels) < labelCount(set.Name) {
			if !wildcardProven(authority, set.Name, s.signer) {
				return Bogus
			}
		}
		return Secure
	}
	_ = lastErr
	return Bogus
}

// zoneSecurityOf decides for an unsigned name: walk up until a zone with
// a known state is found; a proven insecure delegation makes the answer
// insecure, a signed zone makes an unsigned answer bogus.
func (v *Validator) zoneSecurityOf(w *work, name string) Result {
	for n := name; ; n = parentName(n) {
		st := v.zoneKeys(w, n)
		if st != nil {
			if st.insecure {
				return Insecure
			}
			// A signed zone above an unsigned answer: bogus unless a
			// delegation in between is proven insecure, which zoneKeys
			// discovers when it queries the DS of the child names.
			return v.walkDown(w, n, name)
		}
		if n == "" {
			return Bogus
		}
	}
}

// walkDown checks the delegations between a signed zone and name: each
// DS lookup either proves an insecure cut (Insecure) or continues.
func (v *Validator) walkDown(w *work, zone, name string) Result {
	labels := labelsOf(name)
	depth := labelCount(zone)
	for i := len(labels) - depth - 1; i >= 0; i-- {
		child := strings.Join(labels[i:], ".")
		st := v.zoneKeys(w, child)
		if st == nil {
			return Bogus
		}
		if st.insecure {
			return Insecure
		}
	}
	return Bogus
}

// ---- keys and chains -------------------------------------------------------

// zoneKeys returns the trusted keys of zone (or its insecure state),
// building the chain from a trust anchor through DS records; nil means
// bogus or lookups exhausted.
func (v *Validator) zoneKeys(w *work, zone string) *zoneState {
	now := v.now()
	v.mu.Lock()
	if st, ok := v.zones[zone]; ok && now.Before(st.expires) {
		v.mu.Unlock()
		return st
	}
	v.mu.Unlock()
	st := v.buildZone(w, zone, 0)
	if st != nil {
		v.mu.Lock()
		if len(v.zones) >= v.cap {
			for k, s := range v.zones {
				if now.After(s.expires) {
					delete(v.zones, k)
				}
			}
			for k := range v.zones {
				if len(v.zones) < v.cap {
					break
				}
				delete(v.zones, k)
			}
		}
		v.zones[zone] = st
		v.mu.Unlock()
	}
	return st
}

func (v *Validator) buildZone(w *work, zone string, depth int) *zoneState {
	if depth > 16 {
		return nil
	}
	// Trust anchors: the zone's DNSKEY set must be signed by a key that
	// matches an anchor.
	if anchors, ok := v.anchors[zone]; ok {
		keys, exp := v.fetchDNSKEY(w, zone)
		if keys == nil {
			return nil
		}
		trusted := matchDS(keys, anchorsToDS(anchors))
		if len(trusted) == 0 {
			return nil
		}
		return &zoneState{keys: keys.keys, expires: exp}
	}
	if zone == "" {
		return nil // no anchor for the root
	}
	// DS from the parent side.
	ds, parent, negative, exp, ok := v.fetchDS(w, zone)
	if !ok {
		return nil
	}
	pst := v.zoneKeysDepth(w, parent, depth+1)
	if pst == nil {
		return nil
	}
	if pst.insecure {
		return &zoneState{insecure: true, expires: exp}
	}
	if ds == nil {
		// NODATA for DS: the proof must be verified for the parent zone;
		// then the delegation is insecure.
		if negative == nil {
			return nil
		}
		switch v.verifyNegativeDS(negative, zone, parent, pst) {
		case Insecure:
			return &zoneState{insecure: true, expires: exp}
		case Secure:
			// Proven not to be a zone cut: the name is inside the parent
			// and inherits its state, so a walk down through it continues.
			return &zoneState{keys: pst.keys, inside: true, expires: exp}
		default:
			return nil
		}
	}
	if err := v.checkSet(ds, pst.keys); err != nil {
		return nil
	}
	dsRecords := parseDSSet(ds)
	if len(dsRecords) == 0 {
		return nil
	}
	if !anySupportedDS(dsRecords) {
		return &zoneState{insecure: true, expires: exp} // RFC 4035 5.2: unsupported algorithms mean insecure
	}
	keys, kexp := v.fetchDNSKEY(w, zone)
	if keys == nil {
		return nil
	}
	if len(matchDS(keys, dsRecords)) == 0 {
		return nil
	}
	if kexp.Before(exp) {
		exp = kexp
	}
	return &zoneState{keys: keys.keys, expires: exp}
}

func (v *Validator) zoneKeysDepth(w *work, zone string, depth int) *zoneState {
	now := v.now()
	v.mu.Lock()
	if st, ok := v.zones[zone]; ok && now.Before(st.expires) {
		v.mu.Unlock()
		return st
	}
	v.mu.Unlock()
	st := v.buildZone(w, zone, depth)
	if st != nil {
		v.mu.Lock()
		v.zones[zone] = st
		v.mu.Unlock()
	}
	return st
}

// keySet is a DNSKEY RRset with its parsed keys.
type keySet struct {
	set  *RRset
	keys []dnskey
}

// fetchDNSKEY queries the zone's DNSKEY RRset and verifies that it is
// signed by one of its own keys; the caller checks the DS or anchor
// match. Returns nil when unavailable or unsigned.
func (v *Validator) fetchDNSKEY(w *work, zone string) (*keySet, time.Time) {
	m := v.lookup(w, zone, TypeDNSKEY)
	if m == nil {
		return nil, time.Time{}
	}
	var set *RRset
	for _, s := range groupRRsets(m.Answer) {
		if s.Type == TypeDNSKEY && s.Name == zone {
			set = s
		}
	}
	if set == nil || len(set.Sigs) == 0 {
		return nil, time.Time{}
	}
	ks := &keySet{set: set}
	for _, rr := range set.RRs {
		if k, err := parseDNSKEY(rr); err == nil && k.flags&0x100 != 0 { // zone key bit
			ks.keys = append(ks.keys, k)
		}
	}
	if len(ks.keys) == 0 {
		return nil, time.Time{}
	}
	// Self signature by some key of the set.
	exp := v.now().Add(time.Duration(set.TTL) * time.Second)
	if err := v.checkSet(set, ks.keys); err != nil {
		return nil, time.Time{}
	}
	for _, sig := range set.Sigs {
		if s, err := parseRRSIG(sig.Data); err == nil {
			if e := time.Unix(int64(s.expiration), 0); e.Before(exp) {
				exp = e
			}
		}
	}
	return ks, exp
}

// fetchDS queries DS for zone. It returns the DS RRset (or nil), the
// parent zone that answered (from the signer of the DS or the SOA; the
// root is ""), the negative answer for a NODATA response, an expiry and
// whether an answer was obtained at all.
func (v *Validator) fetchDS(w *work, zone string) (*RRset, string, *Message, time.Time, bool) {
	m := v.lookup(w, zone, TypeDS)
	if m == nil {
		return nil, "", nil, time.Time{}, false
	}
	exp := v.now().Add(time.Hour)
	for _, s := range groupRRsets(m.Answer) {
		if s.Type == TypeDS && s.Name == zone && len(s.Sigs) > 0 {
			if sig, err := parseRRSIG(s.Sigs[0].Data); err == nil {
				if e := time.Unix(int64(sig.expiration), 0); e.Before(exp) {
					exp = e
				}
				return s, sig.signer, nil, minTime(exp, v.now().Add(time.Duration(s.TTL)*time.Second)), true
			}
		}
	}
	// Negative: the parent is the signer of the SOA (or NSEC records).
	for _, s := range groupRRsets(m.Authority) {
		if (s.Type == TypeSOA || s.Type == TypeNSEC || s.Type == TypeNSEC3) && len(s.Sigs) > 0 {
			if sig, err := parseRRSIG(s.Sigs[0].Data); err == nil {
				ttl := time.Duration(s.TTL) * time.Second
				return nil, sig.signer, m, minTime(exp, v.now().Add(max(ttl, time.Minute))), true
			}
		}
	}
	// Unsigned negative answer from an unsigned parent: the parent is
	// found by walking up.
	if m.Header.Rcode() == RcodeNoError || m.Header.Rcode() == RcodeNXDomain {
		return nil, parentName(zone), m, v.now().Add(10 * time.Minute), true
	}
	return nil, "", nil, time.Time{}, false
}

// verifyNegativeDS checks that the parent proves the absence of a DS
// record at zone (an insecure delegation), Insecure when it does.
func (v *Validator) verifyNegativeDS(m *Message, zone, parent string, pst *zoneState) Result {
	authority := groupRRsets(m.Authority)
	var nsecs, nsec3s []*RRset
	signed := false
	for _, set := range authority {
		switch set.Type {
		case TypeNSEC:
			if v.checkSet(set, pst.keys) != nil {
				return Bogus
			}
			nsecs = append(nsecs, set)
			signed = true
		case TypeNSEC3:
			if v.checkSet(set, pst.keys) != nil {
				return Bogus
			}
			nsec3s = append(nsec3s, set)
			signed = true
		case TypeSOA:
			if len(set.Sigs) > 0 && v.checkSet(set, pst.keys) != nil {
				return Bogus
			}
		}
	}
	if !signed {
		return Bogus
	}
	if len(nsecs) > 0 {
		// The NSEC matching the delegation must have NS but not DS
		// (Insecure); an NSEC matching a name without NS proves the name
		// is not a zone cut at all (Secure: still inside the parent).
		for _, set := range nsecs {
			for _, rr := range set.RRs {
				if set.Name == zone && isSubdomain(zone, parent) {
					has := nsecTypes(rr.Data)
					if has[TypeDS] {
						return Bogus
					}
					if has[TypeNS] && !has[TypeSOA] {
						return Insecure
					}
					return Secure
				}
			}
		}
		if nsecNameError(nsecs, zone, parent) {
			return Bogus // name does not exist at all: a positive answer below it is bogus
		}
		return Bogus
	}
	// NSEC3: only an explicit Insecure (a delegation without DS, or an
	// opt-out span) makes the cut insecure. A plain NODATA match means the
	// name is not a delegation, so no DS can be asked for and nothing
	// below it is insecure; mapping that to Insecure let an upstream turn
	// validation off for any host name in an NSEC3 zone.
	switch nsec3Denial(nsec3s, zone, TypeDS, parent, false) {
	case Insecure:
		return Insecure
	case Secure:
		return Secure
	}
	return Bogus
}

// answersQuestion reports whether the answer section holds data for the
// question: an RRset at the query name of the query type or a CNAME, a
// DNAME at an ancestor, or records reached through the CNAME chain that
// starts at the query name.
func answersQuestion(answer []*RRset, q Question) bool {
	found := false
	reach := map[string]bool{q.Name: true}
	// CNAME chains are short; a few passes resolve any order.
	for pass := 0; pass < 4; pass++ {
		for _, set := range answer {
			if set.Type == TypeRRSIG || len(set.RRs) == 0 {
				continue
			}
			if set.Type == TypeDNAME && isSubdomain(q.Name, set.Name) && set.Name != q.Name {
				found = true
				continue
			}
			if !reach[set.Name] {
				continue
			}
			if set.Type == q.Type || set.Type == TypeCNAME {
				found = true
			}
			if set.Type == TypeCNAME {
				for _, rr := range set.RRs {
					if target, _, err := readNameCase(rr.Data, 0, false); err == nil {
						reach[target] = true
					}
				}
			}
		}
	}
	return found
}

// lookup asks the upstream for name/type with DO set.
func (v *Validator) lookup(w *work, name string, typ uint16) *Message {
	if w.lookups >= v.MaxLookups || w.ctx.Err() != nil {
		return nil
	}
	w.lookups++
	v.lookups.Add(1)
	q, err := Query(1, name, typ)
	if err != nil {
		return nil
	}
	q = withDO(q)
	qu, qEnd, _ := ParseQuestion(q)
	resp, err := v.resolver.Exchange(w.ctx, q, qEnd, qu, false)
	if err != nil {
		return nil
	}
	m, err := ParseMessage(resp)
	if err != nil {
		return nil
	}
	return m
}

// ---- signatures ------------------------------------------------------------

type rrsig struct {
	covered    uint16
	alg        uint8
	labels     uint8
	origTTL    uint32
	expiration uint32
	inception  uint32
	keyTag     uint16
	signer     string
	signature  []byte
	prefix     []byte // rdata up to and including the signer name
}

func parseRRSIG(data []byte) (*rrsig, error) {
	if len(data) < 19 {
		return nil, errMalformed
	}
	s := &rrsig{covered: binary.BigEndian.Uint16(data), alg: data[2], labels: data[3], origTTL: binary.BigEndian.Uint32(data[4:]),
		expiration: binary.BigEndian.Uint32(data[8:]), inception: binary.BigEndian.Uint32(data[12:]), keyTag: binary.BigEndian.Uint16(data[16:])}
	signer, n, err := readNameCase(data, 18, true)
	if err != nil {
		return nil, err
	}
	s.signer = netutil.ASCIILower(signer)
	s.signature = data[n:]
	s.prefix = data[:n]
	return s, nil
}

func parseDNSKEY(rr RR) (dnskey, error) {
	if len(rr.Data) < 5 {
		return dnskey{}, errMalformed
	}
	k := dnskey{flags: binary.BigEndian.Uint16(rr.Data), alg: rr.Data[3], pub: rr.Data[4:], owner: rr.Name, rdata: rr.Data}
	if rr.Data[2] != 3 {
		return dnskey{}, errors.New("dnskey protocol")
	}
	k.tag = keyTag(rr.Data)
	return k, nil
}

// keyTag computes the RFC 4034 appendix B key tag.
func keyTag(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff) //nolint:gosec // masked
}

// checkSet verifies that some signature of set verifies with some key.
func (v *Validator) checkSet(set *RRset, keys []dnskey) error {
	if len(set.Sigs) == 0 {
		return errors.New("unsigned")
	}
	last := errors.New("no usable signature")
	for _, sig := range set.Sigs {
		s, err := parseRRSIG(sig.Data)
		if err != nil {
			last = err
			continue
		}
		if err := v.checkSignature(set, s, keys); err != nil {
			last = err
			continue
		}
		return nil
	}
	return last
}

// checkSignature verifies one RRSIG over set with the matching key.
func (v *Validator) checkSignature(set *RRset, s *rrsig, keys []dnskey) error {
	if s.covered != set.Type {
		return errors.New("type covered mismatch")
	}
	if !v.timeValid(s) {
		return errors.New("signature expired or not yet valid")
	}
	if int(s.labels) > labelCount(set.Name) {
		return errors.New("labels field larger than the owner")
	}
	signed := v.signedData(set, s)
	for i := range keys {
		k := &keys[i]
		if k.tag != s.keyTag || k.alg != s.alg || k.owner != s.signer {
			continue
		}
		if err := verifySig(k, s.alg, signed, s.signature); err == nil {
			return nil
		}
	}
	return errors.New("no key verifies the signature")
}

func (v *Validator) timeValid(s *rrsig) bool {
	now := uint32(v.now().Unix()) //nolint:gosec // 32 bit serial arithmetic as RFC 4034 section 3.1.5
	skew := uint32(v.Skew.Seconds())
	return int32(s.inception-skew-now) <= 0 && int32(s.expiration+skew-now) >= 0 //nolint:gosec // serial arithmetic
}

// signedData builds RRSIG_RDATA | canonical RRset (RFC 4034 3.1.8.1).
func (v *Validator) signedData(set *RRset, s *rrsig) []byte {
	out := append([]byte{}, s.prefix...)
	owner := canonicalName(set.Name)
	if int(s.labels) < labelCount(owner) {
		ls := labelsOf(owner)
		owner = "*." + strings.Join(ls[len(ls)-int(s.labels):], ".")
	}
	on, _ := packName(owner)
	for _, rdata := range sortedCanonical(set.RRs) {
		out = append(out, on...)
		out = binary.BigEndian.AppendUint16(out, set.Type)
		out = binary.BigEndian.AppendUint16(out, set.Class)
		out = binary.BigEndian.AppendUint32(out, s.origTTL)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata))) //nolint:gosec // rdata bounded by the message
		out = append(out, rdata...)
	}
	return out
}

// verifySig checks a signature over data for the algorithm.
func verifySig(k *dnskey, alg uint8, data, sig []byte) error {
	switch alg {
	case 5, 7, 8, 10: // RSA/SHA-1, RSASHA1-NSEC3, RSA/SHA-256, RSA/SHA-512
		pub, err := parseRSAKey(k.pub)
		if err != nil {
			return err
		}
		var h crypto.Hash
		var sum []byte
		switch alg {
		case 8:
			h = crypto.SHA256
			d := sha256.Sum256(data)
			sum = d[:]
		case 10:
			h = crypto.SHA512
			d := sha512.Sum512(data)
			sum = d[:]
		default:
			h = crypto.SHA1
			d := sha1.Sum(data) //nolint:gosec // algorithm 5 and 7 are SHA-1 by definition
			sum = d[:]
		}
		return rsa.VerifyPKCS1v15(pub, h, sum, sig)
	case 13, 14: // ECDSA P-256/SHA-256, P-384/SHA-384
		curve, size := elliptic.P256(), 32
		var sum []byte
		if alg == 14 {
			curve, size = elliptic.P384(), 48
			d := sha512.Sum384(data)
			sum = d[:]
		} else {
			d := sha256.Sum256(data)
			sum = d[:]
		}
		if len(k.pub) != 2*size || len(sig) != 2*size {
			return errors.New("ecdsa key or signature size")
		}
		x := new(big.Int).SetBytes(k.pub[:size])
		y := new(big.Int).SetBytes(k.pub[size:])
		if !curve.IsOnCurve(x, y) {
			return errors.New("ecdsa key not on curve")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(pub, sum, r, s) {
			return errors.New("ecdsa signature invalid")
		}
		return nil
	case 15: // Ed25519
		if len(k.pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(k.pub), data, sig) {
			return errors.New("ed25519 signature invalid")
		}
		return nil
	}
	return fmt.Errorf("algorithm %d not supported", alg)
}

// parseRSAKey decodes the RFC 3110 exponent/modulus format.
func parseRSAKey(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 3 {
		return nil, errMalformed
	}
	elen := int(b[0])
	off := 1
	if elen == 0 {
		elen = int(binary.BigEndian.Uint16(b[1:]))
		off = 3
	}
	if elen == 0 || off+elen >= len(b) || elen > 4 {
		return nil, errors.New("rsa exponent")
	}
	e := new(big.Int).SetBytes(b[off : off+elen])
	n := new(big.Int).SetBytes(b[off+elen:])
	// A public exponent is odd and at least 3; 0 and 1 are not keys,
	// and an even one cannot be a valid RSA exponent at all.
	if !e.IsInt64() || e.Int64() < 3 || e.Bit(0) == 0 {
		return nil, errors.New("rsa exponent")
	}
	if n.BitLen() < 1024 || n.BitLen() > 4096 {
		return nil, errors.New("rsa modulus size")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func supportedAlg(alg uint8) bool {
	switch alg {
	case 5, 7, 8, 10, 13, 14, 15:
		return true
	}
	return false
}

// ---- DS ---------------------------------------------------------------------

type dsRecord struct {
	keyTag     uint16
	alg        uint8
	digestType uint8
	digest     []byte
}

func parseDSSet(set *RRset) []dsRecord {
	out := make([]dsRecord, 0, len(set.RRs))
	for _, rr := range set.RRs {
		if len(rr.Data) < 5 {
			continue
		}
		out = append(out, dsRecord{keyTag: binary.BigEndian.Uint16(rr.Data), alg: rr.Data[2], digestType: rr.Data[3], digest: rr.Data[4:]})
	}
	return out
}

func anchorsToDS(as []TrustAnchor) []dsRecord {
	out := make([]dsRecord, 0, len(as))
	for _, a := range as {
		out = append(out, dsRecord{keyTag: a.KeyTag, alg: a.Algorithm, digestType: a.DigestType, digest: a.Digest})
	}
	return out
}

func anySupportedDS(ds []dsRecord) bool {
	for _, d := range ds {
		if supportedAlg(d.alg) && (d.digestType == 1 || d.digestType == 2 || d.digestType == 4) {
			return true
		}
	}
	return false
}

// matchDS returns the keys of ks that a DS record vouches for.
func matchDS(ks *keySet, ds []dsRecord) []dnskey {
	var out []dnskey
	owner, _ := packName(ks.set.Name)
	for _, k := range ks.keys {
		for _, d := range ds {
			if d.keyTag != k.tag || d.alg != k.alg {
				continue
			}
			var digest []byte
			input := append(append([]byte{}, owner...), k.rdata...)
			switch d.digestType {
			case 1:
				s := sha1.Sum(input) //nolint:gosec // DS digest type 1 is SHA-1 by definition
				digest = s[:]
			case 2:
				s := sha256.Sum256(input)
				digest = s[:]
			case 4:
				s := sha512.Sum384(input)
				digest = s[:]
			default:
				continue
			}
			if string(digest) == string(d.digest) {
				out = append(out, k)
			}
		}
	}
	return out
}

// ---- NSEC ---------------------------------------------------------------

// nsecTypes decodes a type bitmap into a set.
func nsecTypes(data []byte) map[uint16]bool {
	out := map[uint16]bool{}
	// Skip the next name.
	off := nameLen(data, 0)
	for off+2 <= len(data) {
		window := int(data[off])
		l := int(data[off+1])
		off += 2
		if off+l > len(data) || l > 32 {
			break
		}
		for i := 0; i < l; i++ {
			for bit := 0; bit < 8; bit++ {
				if data[off+i]&(0x80>>bit) != 0 {
					out[uint16(window<<8|i*8+bit)] = true //nolint:gosec // bounded
				}
			}
		}
		off += l
	}
	return out
}

func nsecNext(data []byte) string {
	n, _, err := readNameCase(data, 0, false)
	if err != nil {
		return ""
	}
	return n
}

// nsecCovers reports whether the NSEC at owner with next covers name
// (owner < name < next in canonical order, with the last NSEC wrapping
// to the zone apex).
func nsecCovers(owner, next, name string) bool {
	if canonicalCompare(owner, next) >= 0 { // last record wraps
		return canonicalCompare(name, owner) > 0 || canonicalCompare(name, next) < 0
	}
	return canonicalCompare(name, owner) > 0 && canonicalCompare(name, next) < 0
}

// nsecUsable reports whether an NSEC at owner may prove anything about
// name in zone (RFC 4035 5.4, RFC 6840 4.1): the record and its next name
// must belong to the zone, and an NSEC of a delegation (NS without SOA)
// at an ancestor of name is the parent side of a cut and says nothing
// about names below it.
func nsecUsable(owner, next string, types map[uint16]bool, name, zone string) bool {
	if !isSubdomain(owner, zone) || !isSubdomain(next, zone) {
		return false
	}
	if types[TypeNS] && !types[TypeSOA] && owner != name && isSubdomain(name, owner) {
		return false
	}
	return true
}

// nsecNameError checks an NXDOMAIN proof: an NSEC covering the name and
// one covering the wildcard at the closest encloser, both from zone.
func nsecNameError(sets []*RRset, name, zone string) bool {
	covered, wildcard := false, false
	var encloser string
	for _, set := range sets {
		for _, rr := range set.RRs {
			next := nsecNext(rr.Data)
			if !nsecUsable(set.Name, next, nsecTypes(rr.Data), name, zone) {
				continue
			}
			if nsecCovers(set.Name, next, name) {
				covered = true
				// Closest encloser: the longest common ancestor of the
				// owner or next name and the query name.
				encloser = commonAncestor(set.Name, name)
				if c := commonAncestor(next, name); labelCount(c) > labelCount(encloser) {
					encloser = c
				}
			}
		}
	}
	if !covered {
		return false
	}
	wc := "*." + encloser
	if encloser == "" {
		wc = "*"
	}
	if !isSubdomain(encloser, zone) {
		return false
	}
	for _, set := range sets {
		for _, rr := range set.RRs {
			next := nsecNext(rr.Data)
			if !nsecUsable(set.Name, next, nsecTypes(rr.Data), wc, zone) {
				continue
			}
			if nsecCovers(set.Name, next, wc) || set.Name == wc {
				wildcard = true
			}
		}
	}
	return wildcard
}

// nsecNoData checks a NODATA proof: an NSEC at the name without the type
// (and not a CNAME); or a wildcard NSEC matching without the type. Both
// must belong to zone, and an NSEC of a delegation proves NODATA only for
// DS (any other type lives in the child zone).
func nsecNoData(sets []*RRset, name string, typ uint16, zone string) bool {
	for _, set := range sets {
		for _, rr := range set.RRs {
			if set.Name == name || (strings.HasPrefix(set.Name, "*.") && isSubdomain(name, set.Name[2:])) {
				types := nsecTypes(rr.Data)
				if !nsecUsable(set.Name, nsecNext(rr.Data), types, name, zone) {
					continue
				}
				if types[TypeNS] && !types[TypeSOA] && typ != TypeDS {
					continue
				}
				if !types[typ] && !types[TypeCNAME] {
					return true
				}
			}
		}
	}
	return false
}

// wildcardProven checks that authority proves the query name does not
// exist itself (needed for a wildcard expanded answer).
func wildcardProven(authority []*RRset, name, zone string) bool {
	var nsecs, nsec3s []*RRset
	for _, set := range authority {
		switch set.Type {
		case TypeNSEC:
			nsecs = append(nsecs, set)
		case TypeNSEC3:
			nsec3s = append(nsec3s, set)
		}
	}
	for _, set := range nsecs {
		for _, rr := range set.RRs {
			if nsecCovers(set.Name, nsecNext(rr.Data), name) {
				return true
			}
		}
	}
	if len(nsec3s) > 0 {
		// The next closer name must be covered.
		for _, set := range nsec3s {
			p, err := nsec3Set(set)
			if err != nil {
				continue
			}
			labels := labelsOf(name)
			for i := 0; i < len(labels); i++ {
				h := nsec3Hash(strings.Join(labels[i:], "."), p)
				if nsec3Covers(set, h, zone) {
					return true
				}
			}
		}
	}
	return false
}

func commonAncestor(a, b string) string {
	la, lb := labelsOf(a), labelsOf(b)
	n := 0
	for n < len(la) && n < len(lb) && netutil.ASCIIEqualFold(la[len(la)-1-n], lb[len(lb)-1-n]) {
		n++
	}
	if n == 0 {
		return ""
	}
	return strings.Join(lb[len(lb)-n:], ".")
}

// ---- NSEC3 ----------------------------------------------------------------

type nsec3 struct {
	hashAlg    uint8
	flags      uint8
	iterations uint16
	salt       []byte
	next       []byte
	types      map[uint16]bool
}

func parseNSEC3(rr RR) (*nsec3, error) {
	d := rr.Data
	if len(d) < 6 {
		return nil, errMalformed
	}
	p := &nsec3{hashAlg: d[0], flags: d[1], iterations: binary.BigEndian.Uint16(d[2:])}
	sl := int(d[4])
	if 5+sl+1 > len(d) {
		return nil, errMalformed
	}
	p.salt = d[5 : 5+sl]
	hl := int(d[5+sl])
	off := 6 + sl
	if off+hl > len(d) {
		return nil, errMalformed
	}
	p.next = d[off : off+hl]
	// The type bitmap follows; reuse the NSEC decoder with a fake name prefix.
	p.types = nsecTypes(append([]byte{0}, d[off+hl:]...))
	return p, nil
}

var base32hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// nsec3Hash hashes a name with the record's parameters (SHA-1 only,
// iterations bounded as RFC 9276 recommends).
func nsec3Hash(name string, p *nsec3) []byte {
	if p == nil || p.hashAlg != 1 || p.iterations > 150 {
		return nil
	}
	wire, err := packName(netutil.ASCIILower(name))
	if err != nil {
		return nil
	}
	h := sha1.Sum(append(wire, p.salt...)) //nolint:gosec // NSEC3 hashing is SHA-1 by specification
	for i := 0; i < int(p.iterations); i++ {
		h = sha1.Sum(append(h[:], p.salt...)) //nolint:gosec // as above
	}
	return h[:]
}

// nsec3Owner decodes the hashed owner label of an NSEC3 record.
func nsec3Owner(set *RRset, zone string) []byte {
	label := set.Name
	if zone != "" {
		label = strings.TrimSuffix(set.Name, "."+zone)
	}
	b, err := base32hex.DecodeString(strings.ToUpper(label))
	if err != nil {
		return nil
	}
	return b
}

func nsec3Covers(set *RRset, hash []byte, zone string) bool {
	if hash == nil {
		return false
	}
	owner := nsec3Owner(set, zone)
	p, err := nsec3Set(set)
	if err != nil || owner == nil {
		return false
	}
	if string(owner) >= string(p.next) { // last record wraps
		return string(hash) > string(owner) || string(hash) < string(p.next)
	}
	return string(hash) > string(owner) && string(hash) < string(p.next)
}

func nsec3Matches(set *RRset, hash []byte, zone string) *nsec3 {
	if hash == nil || string(nsec3Owner(set, zone)) != string(hash) {
		return nil
	}
	p, err := nsec3Set(set)
	if err != nil {
		return nil
	}
	return p
}

// nsec3Set returns the NSEC3 parameters of an RRset's first record. A
// lone RRSIG covering NSEC3 groups into an RRset with signatures and no
// records, so the record must never be indexed unchecked.
func nsec3Set(set *RRset) (*nsec3, error) {
	if set == nil || len(set.RRs) == 0 {
		return nil, errMalformed
	}
	return parseNSEC3(set.RRs[0])
}

// nsec3Denial checks NSEC3 proofs (RFC 5155 section 8): NODATA needs a
// matching record without the type; NXDOMAIN needs the closest encloser
// proof plus covering records for the next closer name and the
// wildcard. An opt-out span covering a DS query means insecure.
func nsec3Denial(sets []*RRset, name string, typ uint16, zone string, nxdomain bool) Result {
	if len(sets) == 0 {
		return Bogus
	}
	params, err := nsec3Set(sets[0])
	if err != nil {
		return Bogus // a malformed or empty NSEC3 set proves nothing
	}
	if nsec3Hash(name, params) == nil {
		return Insecure // unsupported parameters: treat as insecure (RFC 5155 8.1)
	}
	if !isSubdomain(name, zone) {
		return Bogus
	}
	if !nxdomain {
		h := nsec3Hash(name, params)
		for _, set := range sets {
			if p := nsec3Matches(set, h, zone); p != nil {
				if !p.types[typ] && !p.types[TypeCNAME] {
					if p.types[TypeNS] && !p.types[TypeSOA] {
						if typ == TypeDS {
							return Insecure // a delegation without DS
						}
						return Bogus // the parent side of a cut answers only for DS
					}
					return Secure
				}
				return Bogus
			}
		}
		// No exact match: a wildcard match or an opt-out span for DS.
		if typ == TypeDS {
			for _, set := range sets {
				if nsec3Covers(set, h, zone) {
					if p, err := nsec3Set(set); err == nil && p.flags&1 == 1 {
						return Insecure // opt-out
					}
				}
			}
		}
	}
	// Closest encloser proof.
	labels := labelsOf(name)
	for i := 1; i <= len(labels); i++ {
		encloser := strings.Join(labels[i:], ".")
		if !isSubdomain(encloser, zone) {
			break
		}
		eh := nsec3Hash(encloser, params)
		var match *nsec3
		for _, set := range sets {
			if match = nsec3Matches(set, eh, zone); match != nil {
				break
			}
		}
		if match == nil {
			continue
		}
		if match.types[TypeNS] && !match.types[TypeSOA] {
			// The closest encloser is a delegation: the name lives in the
			// child zone and this zone cannot deny it (RFC 5155 8.3).
			return Bogus
		}
		nextCloser := strings.Join(labels[i-1:], ".")
		nch := nsec3Hash(nextCloser, params)
		coveredNext, optOut := false, false
		for _, set := range sets {
			if nsec3Covers(set, nch, zone) {
				coveredNext = true
				if p, err := nsec3Set(set); err == nil && p.flags&1 == 1 {
					optOut = true
				}
			}
		}
		if !coveredNext {
			return Bogus
		}
		if nxdomain {
			wh := nsec3Hash("*."+encloser, params)
			for _, set := range sets {
				if nsec3Covers(set, wh, zone) {
					return Secure
				}
			}
			if optOut {
				return Insecure
			}
			return Bogus
		}
		// NODATA under a wildcard, or a DS in an opt-out span.
		if optOut && typ == TypeDS {
			return Insecure
		}
		wh := nsec3Hash("*."+encloser, params)
		for _, set := range sets {
			if p := nsec3Matches(set, wh, zone); p != nil && !p.types[typ] {
				return Secure
			}
		}
		return Bogus
	}
	return Bogus
}

// ---- EDNS helpers -----------------------------------------------------------

// withDO returns query with an OPT record advertising 4096 bytes and the
// DO bit (an existing OPT is replaced).
func withDO(query []byte) []byte {
	m, err := ParseMessage(query)
	if err != nil {
		return query
	}
	var add []RR
	for _, rr := range m.Additional {
		if rr.Type != TypeOPT {
			add = append(add, rr)
		}
	}
	add = append(add, RR{Name: "", Type: TypeOPT, Class: 4096, TTL: ednsDO})
	m.Additional = add
	packed, ok := m.Pack()
	if !ok {
		return query
	}
	return packed
}

// clientDO reports whether a query carries an OPT with DO and whether it
// carries any OPT.
func clientDO(m *Message) (do, opt bool) {
	for _, rr := range m.Additional {
		if rr.Type == TypeOPT {
			return rr.TTL&ednsDO != 0, true
		}
	}
	return false, false
}

// StripDNSSEC removes RRSIG, NSEC and NSEC3 records (unless asked for)
// from a response for a client that did not set DO, and the OPT record
// when the client sent none. It returns resp untouched when nothing
// needs to change.
func StripDNSSEC(resp []byte, query *Message) []byte {
	do, opt := clientDO(query)
	if do {
		return resp
	}
	m, err := ParseMessage(resp)
	if err != nil {
		return resp
	}
	keep := func(rrs []RR) ([]RR, bool) {
		out := rrs[:0:0]
		changed := false
		for _, rr := range rrs {
			switch rr.Type {
			case TypeRRSIG, TypeNSEC, TypeNSEC3:
				if rr.Type == m.Question.Type {
					out = append(out, rr)
				} else {
					changed = true
				}
			case TypeOPT:
				if opt {
					out = append(out, rr)
				} else {
					changed = true
				}
			default:
				out = append(out, rr)
			}
		}
		return out, changed
	}
	var c1, c2, c3 bool
	m.Answer, c1 = keep(m.Answer)
	m.Authority, c2 = keep(m.Authority)
	m.Additional, c3 = keep(m.Additional)
	if !c1 && !c2 && !c3 {
		return resp
	}
	packed, ok := m.Pack()
	if !ok {
		return resp
	}
	return packed
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
