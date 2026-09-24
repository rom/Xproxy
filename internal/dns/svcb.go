package dns

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// SVCB and HTTPS records (RFC 9460), and the discovery of designated
// resolvers (RFC 9462).
//
// These two record types carry what used to need a round trip to find
// out: which protocols an endpoint speaks, on which port, at which
// addresses, and — the reason this matters here — the ECH configuration
// a client needs before it can encrypt its ClientHello. A client that
// cannot read the HTTPS record cannot use ECH at all, which makes the
// record half of that feature rather than an optional extra.
//
// Discovery (DDR) is the same mechanism pointed at the resolver itself.
// A client that was handed this proxy's address by DHCP asks
// _dns.resolver.arpa for SVCB records, and the answer says "the same
// service also speaks DoT here, DoH there, DoQ on this port, and its
// certificate says dns.example.com". The client verifies that
// certificate and upgrades itself from plaintext DNS to an encrypted
// transport without anything being configured.

const (
	// TypeSVCB and TypeHTTPS are RFC 9460's record types.
	TypeSVCB  = 64
	TypeHTTPS = 65
)

// Service parameter keys (RFC 9460 section 14.3.2).
const (
	svcParamMandatory     = 0
	svcParamALPN          = 1
	svcParamNoDefaultALPN = 2
	svcParamPort          = 3
	svcParamIPv4Hint      = 4
	svcParamECH           = 5
	svcParamIPv6Hint      = 6
	svcParamDoHPath       = 7 // RFC 9461
)

// svcParamNames maps the configuration spelling to the key.
var svcParamNames = map[string]uint16{
	"mandatory": svcParamMandatory, "alpn": svcParamALPN, "no-default-alpn": svcParamNoDefaultALPN,
	"port": svcParamPort, "ipv4hint": svcParamIPv4Hint, "ech": svcParamECH,
	"ipv6hint": svcParamIPv6Hint, "dohpath": svcParamDoHPath,
}

// SVCBParam is one key and its encoded value.
type SVCBParam struct {
	Key   uint16
	Value []byte
}

// SVCB is one record: a priority, a target name, and parameters. A
// priority of zero makes it an alias, which carries no parameters.
type SVCB struct {
	Priority uint16
	Target   string
	Params   []SVCBParam
}

// ParamName gives a key its configuration spelling.
func ParamName(key uint16) string {
	for n, k := range svcParamNames {
		if k == key {
			return n
		}
	}
	return "key" + strconv.Itoa(int(key))
}

// ParseSVCBParam builds one parameter from its configuration form. The
// value spellings follow the presentation format in RFC 9460 section 2.1
// so that a record written here and one written in a zone file mean the
// same thing.
func ParseSVCBParam(name, value string) (SVCBParam, error) {
	key, ok := svcParamNames[name]
	if !ok {
		n, err := strconv.Atoi(strings.TrimPrefix(name, "key"))
		if err != nil || !strings.HasPrefix(name, "key") || n < 0 || n > 65535 {
			return SVCBParam{}, fmt.Errorf("unknown service parameter %q", name)
		}
		key = uint16(n) //nolint:gosec // bounded above
	}
	switch key {
	case svcParamALPN:
		var out []byte
		for _, a := range strings.Split(value, ",") {
			a = strings.TrimSpace(a)
			if a == "" || len(a) > 255 {
				return SVCBParam{}, fmt.Errorf("alpn: %q is not a protocol identifier", a)
			}
			out = append(out, byte(len(a)))
			out = append(out, a...)
		}
		if len(out) == 0 {
			return SVCBParam{}, errors.New("alpn: at least one protocol is required")
		}
		return SVCBParam{Key: key, Value: out}, nil
	case svcParamNoDefaultALPN:
		if value != "" {
			return SVCBParam{}, errors.New("no-default-alpn takes no value")
		}
		return SVCBParam{Key: key}, nil
	case svcParamPort:
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 65535 {
			return SVCBParam{}, fmt.Errorf("port: %q is not a port", value)
		}
		return SVCBParam{Key: key, Value: []byte{byte(n >> 8), byte(n)}}, nil
	case svcParamIPv4Hint, svcParamIPv6Hint:
		var out []byte
		for _, a := range strings.Split(value, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(a))
			if err != nil {
				return SVCBParam{}, fmt.Errorf("%s: %q is not an address", ParamName(key), a)
			}
			if key == svcParamIPv4Hint {
				if !addr.Is4() {
					return SVCBParam{}, fmt.Errorf("ipv4hint: %q is not an IPv4 address", a)
				}
				b := addr.As4()
				out = append(out, b[:]...)
			} else {
				if addr.Is4() {
					return SVCBParam{}, fmt.Errorf("ipv6hint: %q is not an IPv6 address", a)
				}
				b := addr.As16()
				out = append(out, b[:]...)
			}
		}
		if len(out) == 0 {
			return SVCBParam{}, errors.New("address hint is empty")
		}
		return SVCBParam{Key: key, Value: out}, nil
	case svcParamECH:
		raw, err := base64.StdEncoding.DecodeString(strings.Trim(value, `"`))
		if err != nil {
			return SVCBParam{}, fmt.Errorf("ech: %w", err)
		}
		if len(raw) < 4 {
			return SVCBParam{}, errors.New("ech: too short to be an ECHConfigList")
		}
		return SVCBParam{Key: key, Value: raw}, nil
	case svcParamDoHPath:
		if !strings.HasPrefix(value, "/") {
			return SVCBParam{}, errors.New("dohpath: must start with /")
		}
		// RFC 9461: the path is a URI template and must carry the dns
		// variable, or a client cannot build a query from it.
		if !strings.Contains(value, "{?dns}") {
			return SVCBParam{}, errors.New(`dohpath: must contain the {?dns} template variable`)
		}
		return SVCBParam{Key: key, Value: []byte(value)}, nil
	case svcParamMandatory:
		var out []byte
		for _, n := range strings.Split(value, ",") {
			k, ok := svcParamNames[strings.TrimSpace(n)]
			if !ok {
				return SVCBParam{}, fmt.Errorf("mandatory: unknown parameter %q", n)
			}
			out = append(out, byte(k>>8), byte(k))
		}
		return SVCBParam{Key: key, Value: out}, nil
	default:
		return SVCBParam{Key: key, Value: []byte(value)}, nil
	}
}

// Encode writes the record's RDATA. Parameters are sorted by key, which
// RFC 9460 requires and which also makes two records with the same
// content encode identically.
func (s SVCB) Encode() ([]byte, error) {
	name, err := packName(s.Target)
	if err != nil {
		return nil, err
	}
	out := []byte{byte(s.Priority >> 8), byte(s.Priority)}
	out = append(out, name...)
	if s.Priority == 0 {
		// An alias form carries no parameters; sending some would make
		// the record ambiguous.
		if len(s.Params) > 0 {
			return nil, errors.New("an alias record (priority 0) takes no parameters")
		}
		return out, nil
	}
	params := append([]SVCBParam(nil), s.Params...)
	sort.Slice(params, func(i, j int) bool { return params[i].Key < params[j].Key })
	seen := map[uint16]bool{}
	for _, p := range params {
		if seen[p.Key] {
			return nil, fmt.Errorf("service parameter %s appears twice", ParamName(p.Key))
		}
		seen[p.Key] = true
		if len(p.Value) > 65535 {
			return nil, fmt.Errorf("service parameter %s is too long", ParamName(p.Key))
		}
		out = append(out, byte(p.Key>>8), byte(p.Key), byte(len(p.Value)>>8), byte(len(p.Value)))
		out = append(out, p.Value...)
	}
	return out, nil
}

// ParseSVCB decodes RDATA. It is used to read a record back, and by the
// tests; the proxy forwards unknown types untouched.
func ParseSVCB(rdata []byte) (SVCB, error) {
	if len(rdata) < 3 {
		return SVCB{}, errors.New("svcb: too short")
	}
	var s SVCB
	s.Priority = uint16(rdata[0])<<8 | uint16(rdata[1])
	name, n, err := readName(rdata, 2)
	if err != nil {
		return SVCB{}, fmt.Errorf("svcb target: %w", err)
	}
	s.Target = name
	if n > len(rdata) {
		return SVCB{}, errors.New("svcb: target past the record")
	}
	rest := rdata[n:]
	var last uint16
	first := true
	for len(rest) > 0 {
		if len(rest) < 4 {
			return SVCB{}, errors.New("svcb: truncated parameter")
		}
		key := uint16(rest[0])<<8 | uint16(rest[1])
		length := int(rest[2])<<8 | int(rest[3])
		if len(rest) < 4+length {
			return SVCB{}, errors.New("svcb: parameter longer than the record")
		}
		if !first && key <= last {
			// RFC 9460 section 2.2: parameters are in ascending key
			// order and appear once. Out of order means a record built
			// by something that does not follow the spec, and accepting
			// it would let two encodings mean the same thing.
			return SVCB{}, errors.New("svcb: parameters out of order or repeated")
		}
		last, first = key, false
		s.Params = append(s.Params, SVCBParam{Key: key, Value: append([]byte(nil), rest[4:4+length]...)})
		rest = rest[4+length:]
	}
	if s.Priority == 0 && len(s.Params) > 0 {
		return SVCB{}, errors.New("svcb: an alias record carries parameters")
	}
	return s, nil
}

// String renders a record in presentation format, for logs and the
// management view.
func (s SVCB) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %s", s.Priority, s.Target)
	for _, p := range s.Params {
		b.WriteByte(' ')
		b.WriteString(ParamName(p.Key))
		switch p.Key {
		case svcParamNoDefaultALPN:
		case svcParamALPN:
			b.WriteByte('=')
			rest := p.Value
			first := true
			for len(rest) > 0 {
				n := int(rest[0])
				if len(rest) < 1+n {
					break
				}
				if !first {
					b.WriteByte(',')
				}
				b.Write(rest[1 : 1+n])
				rest = rest[1+n:]
				first = false
			}
		case svcParamPort:
			if len(p.Value) == 2 {
				fmt.Fprintf(&b, "=%d", int(p.Value[0])<<8|int(p.Value[1]))
			}
		case svcParamIPv4Hint, svcParamIPv6Hint:
			b.WriteByte('=')
			size := 4
			if p.Key == svcParamIPv6Hint {
				size = 16
			}
			for i := 0; i+size <= len(p.Value); i += size {
				if i > 0 {
					b.WriteByte(',')
				}
				if a, ok := netip.AddrFromSlice(p.Value[i : i+size]); ok {
					b.WriteString(a.String())
				}
			}
		case svcParamECH:
			fmt.Fprintf(&b, "=%q", base64.StdEncoding.EncodeToString(p.Value))
		default:
			fmt.Fprintf(&b, "=%q", string(p.Value))
		}
	}
	return b.String()
}

// LocalRecord is an SVCB or HTTPS record this resolver answers itself,
// without asking an upstream. Two things need it: publishing ECH
// configurations for names this proxy terminates, and DDR.
type LocalRecord struct {
	// Name the record is published for, lower case, no trailing dot.
	Name string
	// Type is TypeHTTPS, TypeSVCB, TypeA, TypeAAAA, TypeTXT or TypePTR.
	Type uint16
	TTL  uint32
	// SVCB carries the parameters of an SVCB or HTTPS record.
	SVCB SVCB
	// Addr is the address of an A or AAAA record.
	Addr netip.Addr
	// Text is the string of a TXT record or the name of a PTR record.
	Text string
}

// Rdata encodes the record's own data, in wire form. It is exported so
// that a record which cannot be encoded -- an A record holding an IPv6
// address, a TXT string over 255 bytes -- is a load error rather than a
// record silently skipped when a client asks for it.
func (r LocalRecord) Rdata() ([]byte, error) {
	switch r.Type {
	case TypeA:
		if !r.Addr.Is4() {
			return nil, errors.New("an A record needs an IPv4 address")
		}
		b := r.Addr.As4()
		return b[:], nil
	case TypeAAAA:
		if !r.Addr.Is6() || r.Addr.Is4In6() {
			return nil, errors.New("an AAAA record needs an IPv6 address")
		}
		b := r.Addr.As16()
		return b[:], nil
	case TypeTXT:
		// One character string, which is what fits in 255 bytes and what
		// every reader of a single-string TXT record expects.
		if len(r.Text) > 255 {
			return nil, errors.New("a TXT string longer than 255 bytes")
		}
		return append([]byte{byte(len(r.Text))}, r.Text...), nil
	case TypePTR, TypeCNAME:
		// Both carry a name and nothing else: a PTR's target, and the
		// name a policy zone's local data points at.
		return packName(r.Text)
	default:
		return r.SVCB.Encode()
	}
}

// LocalRecords answers queries from a small static set. A name in the
// set is answered authoritatively for the types it holds, and NODATA
// for the ones it does not — never forwarded, since a forwarded answer
// would contradict the local one.
type LocalRecords struct {
	byName map[string][]LocalRecord
}

// NewLocalRecords compiles a set.
func NewLocalRecords(recs []LocalRecord) *LocalRecords {
	if len(recs) == 0 {
		return nil
	}
	l := &LocalRecords{byName: map[string][]LocalRecord{}}
	for _, r := range recs {
		name := strings.ToLower(strings.TrimSuffix(r.Name, "."))
		l.byName[name] = append(l.byName[name], r)
	}
	return l
}

// Names lists the names served, for the status view.
func (l *LocalRecords) Names() []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, len(l.byName))
	for n := range l.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the records for a question, and whether the name is
// one this resolver owns.
func (l *LocalRecords) Lookup(q Question) (recs []LocalRecord, owned bool) {
	if l == nil {
		return nil, false
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	all, ok := l.byName[name]
	if !ok {
		return nil, false
	}
	for _, r := range all {
		if q.Type == r.Type || q.Type == TypeANY {
			recs = append(recs, r)
		}
	}
	return recs, true
}

// DiscoveryName is the name a client asks to find its resolver's
// encrypted endpoints (RFC 9462).
const DiscoveryName = "_dns.resolver.arpa"

// Designated describes one encrypted endpoint of this resolver.
type Designated struct {
	// Transport is dot, doh or doq.
	Transport string
	// Name is the certificate name clients verify.
	Name string
	// Port is the port the endpoint listens on.
	Port int
	// DoHPath is the URI template for doh.
	DoHPath string
	// IPv4 and IPv6 are address hints, so a client need not resolve
	// the name it was just given.
	IPv4, IPv6 []string
}

// DiscoveryRecords builds the SVCB records for _dns.resolver.arpa from
// a list of endpoints. Priorities follow the order given: an operator
// who lists DoQ first means clients should prefer it.
func DiscoveryRecords(eps []Designated, ttl uint32) ([]LocalRecord, error) {
	out := make([]LocalRecord, 0, len(eps))
	for i, ep := range eps {
		var alpn string
		switch ep.Transport {
		case "dot":
			alpn = "dot"
		case "doq":
			alpn = ALPNDoQ
		case "doh":
			// RFC 9461: an HTTP based designated resolver advertises
			// the HTTP versions it speaks, not "doh".
			alpn = "h2,h3"
		default:
			return nil, fmt.Errorf("discovery[%d]: transport must be dot, doh or doq", i)
		}
		rec := SVCB{Priority: uint16(i + 1), Target: ep.Name} //nolint:gosec // bounded by the list length
		p, err := ParseSVCBParam("alpn", alpn)
		if err != nil {
			return nil, err
		}
		rec.Params = append(rec.Params, p)
		if ep.Port > 0 {
			p, err := ParseSVCBParam("port", strconv.Itoa(ep.Port))
			if err != nil {
				return nil, err
			}
			rec.Params = append(rec.Params, p)
		}
		if ep.Transport == "doh" {
			path := ep.DoHPath
			if path == "" {
				path = DefaultDoHPath
			}
			if !strings.Contains(path, "{?dns}") {
				path += "{?dns}"
			}
			p, err := ParseSVCBParam("dohpath", path)
			if err != nil {
				return nil, err
			}
			rec.Params = append(rec.Params, p)
		}
		for _, hint := range []struct {
			name string
			vals []string
		}{{"ipv4hint", ep.IPv4}, {"ipv6hint", ep.IPv6}} {
			if len(hint.vals) == 0 {
				continue
			}
			p, err := ParseSVCBParam(hint.name, strings.Join(hint.vals, ","))
			if err != nil {
				return nil, fmt.Errorf("discovery[%d]: %w", i, err)
			}
			rec.Params = append(rec.Params, p)
		}
		out = append(out, LocalRecord{Name: DiscoveryName, Type: TypeSVCB, TTL: ttl, SVCB: rec})
	}
	return out, nil
}

// AnswerLocal builds a reply carrying the local records for a question.
// An owned name with no record of the asked type gets NOERROR with no
// answers — which is the truthful answer, and the one that stops a
// client retrying.
func AnswerLocal(query []byte, qEnd int, h Header, q Question, recs []LocalRecord) []byte {
	out := Reply(query, qEnd, h, RcodeNoError)
	// The answer is this resolver's own, so it is authoritative: a
	// client that checks the AA bit should see it set rather than
	// wonder where the record came from.
	setAuthoritative(out)
	if len(recs) == 0 {
		return out
	}
	count := 0
	for _, r := range recs {
		rdata, err := r.Rdata()
		if err != nil || len(rdata) > 65535 {
			continue
		}
		rr := []byte{0xc0, headerLen} // a pointer to the question's name
		rr = append(rr, byte(r.Type>>8), byte(r.Type))
		rr = append(rr, byte(q.Class>>8), byte(q.Class))
		rr = append(rr, byte(r.TTL>>24), byte(r.TTL>>16), byte(r.TTL>>8), byte(r.TTL))
		rr = append(rr, byte(len(rdata)>>8), byte(len(rdata)))
		rr = append(rr, rdata...)
		out = append(out, rr...)
		count++
	}
	out[6] = byte(count >> 8)
	out[7] = byte(count)
	return out
}

// setAuthoritative sets the AA bit on a reply.
func setAuthoritative(out []byte) {
	if len(out) >= 4 {
		out[2] |= 0x04
	}
}
