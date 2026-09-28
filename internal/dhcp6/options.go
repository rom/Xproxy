package dhcp6

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The option codes of RFC 8415 and the ones that matter around it. The registry
// is IANA's; these are the ones a relay can say something about.
const (
	OptionClientID      uint16 = 1  // RFC 8415 s21.2
	OptionServerID      uint16 = 2  // RFC 8415 s21.3
	OptionIANA          uint16 = 3  // identity association for non-temporary addresses
	OptionIATA          uint16 = 4  // for temporary addresses
	OptionIAAddr        uint16 = 5  // an address inside an IA
	OptionORO           uint16 = 6  // the options a client asks for
	OptionPreference    uint16 = 7  // which server a client should prefer
	OptionElapsedTime   uint16 = 8  // how long the client has been trying
	OptionRelayMsg      uint16 = 9  // the message a relay is carrying
	OptionAuth          uint16 = 11 // RFC 8415 s21.11, which nobody deploys
	OptionUnicast       uint16 = 12 // "address me directly", which bypasses the relay
	OptionStatusCode    uint16 = 13
	OptionRapidCommit   uint16 = 14
	OptionUserClass     uint16 = 15
	OptionVendorClass   uint16 = 16
	OptionVendorOpts    uint16 = 17
	OptionInterfaceID   uint16 = 18 // the relay's own: which circuit
	OptionReconfMsg     uint16 = 19
	OptionReconfAccept  uint16 = 20
	OptionSIPServerD    uint16 = 21 // RFC 3319
	OptionSIPServerA    uint16 = 22
	OptionDNSServers    uint16 = 23 // RFC 3646
	OptionDomainList    uint16 = 24
	OptionIAPD          uint16 = 25 // RFC 8415 s21.21: prefix delegation
	OptionIAPrefix      uint16 = 26
	OptionNISServers    uint16 = 27 // RFC 3898
	OptionNISPServers   uint16 = 28
	OptionNISDomain     uint16 = 29
	OptionNISPDomain    uint16 = 30
	OptionSNTPServers   uint16 = 31 // RFC 4075
	OptionInfoRefresh   uint16 = 32 // RFC 8415 s21.23
	OptionRemoteID      uint16 = 37 // RFC 4649, the relay's own
	OptionSubscriberID  uint16 = 38 // RFC 4580, the relay's own
	OptionClientFQDN    uint16 = 39 // RFC 4704
	OptionNewPOSIXTZ    uint16 = 41 // RFC 4833
	OptionNewTZDB       uint16 = 42
	OptionBootFileURL   uint16 = 59 // RFC 5970: what a machine boots
	OptionBootFileParam uint16 = 60
	OptionClientArch    uint16 = 61
	OptionNII           uint16 = 62
	OptionAFTRName      uint16 = 64 // RFC 6334: a DS-Lite tunnel endpoint
	OptionNTPServer     uint16 = 56 // RFC 5908
	OptionPDExclude     uint16 = 67 // RFC 6603
	OptionSOLMaxRT      uint16 = 82
	OptionINFMaxRT      uint16 = 83
	OptionPCPServer     uint16 = 86 // RFC 7291
	OptionDHCP4oDHCP6   uint16 = 88 // RFC 7341: a DHCPv4-over-DHCPv6 server
	OptionS46ContMAPE   uint16 = 94 // RFC 7598: the S46 transition containers
	OptionS46ContMAPT   uint16 = 95
	OptionS46ContLW     uint16 = 96
	OptionS46RuleV4V6   uint16 = 97
	OptionCaptivePortal uint16 = 103 // RFC 8910: a URL the client opens
	OptionSZTPRedirect  uint16 = 136 // RFC 8572: a bootstrap server
)

var optionNames = map[uint16]string{
	OptionClientID: "client_id", OptionServerID: "server_id",
	OptionIANA: "ia_na", OptionIATA: "ia_ta", OptionIAAddr: "ia_addr",
	OptionORO: "option_request", OptionPreference: "preference",
	OptionElapsedTime: "elapsed_time", OptionRelayMsg: "relay_message",
	OptionAuth: "auth", OptionUnicast: "unicast", OptionStatusCode: "status_code",
	OptionRapidCommit: "rapid_commit", OptionUserClass: "user_class",
	OptionVendorClass: "vendor_class", OptionVendorOpts: "vendor_opts",
	OptionInterfaceID: "interface_id", OptionReconfMsg: "reconfigure_message",
	OptionReconfAccept: "reconfigure_accept",
	OptionSIPServerD:   "sip_domains", OptionSIPServerA: "sip_servers",
	OptionDNSServers: "dns_servers", OptionDomainList: "domain_search",
	OptionIAPD: "ia_pd", OptionIAPrefix: "ia_prefix",
	OptionNISServers: "nis_servers", OptionNISPServers: "nisplus_servers",
	OptionNISDomain: "nis_domain", OptionNISPDomain: "nisplus_domain",
	OptionSNTPServers: "sntp_servers", OptionInfoRefresh: "information_refresh_time",
	OptionRemoteID: "remote_id", OptionSubscriberID: "subscriber_id",
	OptionClientFQDN: "client_fqdn", OptionNewPOSIXTZ: "posix_timezone",
	OptionNewTZDB: "tzdb_timezone", OptionBootFileURL: "boot_file_url",
	OptionBootFileParam: "boot_file_parameters", OptionClientArch: "client_architecture",
	OptionNII: "network_interface_id", OptionAFTRName: "aftr_name",
	OptionNTPServer: "ntp_server", OptionPDExclude: "pd_exclude",
	OptionSOLMaxRT: "solicit_max_rt", OptionINFMaxRT: "information_max_rt",
	OptionPCPServer: "pcp_server", OptionDHCP4oDHCP6: "dhcp4_over_dhcp6_server",
	OptionS46ContMAPE: "s46_mape", OptionS46ContMAPT: "s46_mapt",
	OptionS46ContLW: "s46_lightweight_4over6", OptionS46RuleV4V6: "s46_v4v6_binding",
	OptionCaptivePortal: "captive_portal", OptionSZTPRedirect: "sztp_redirect",
}

// OptionName is an option's name, or a decimal rendering of a code this relay
// does not know.
func OptionName(code uint16) string {
	if s, ok := optionNames[code]; ok {
		return s
	}
	return "option_" + strconv.Itoa(int(code))
}

// OptionOf reads an option code by the name a configuration uses, or by a bare
// number for one this relay has no name for.
func OptionOf(s string) (uint16, bool) {
	for code, name := range optionNames {
		if name == s {
			return code, true
		}
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 65535 {
		return uint16(n), true //nolint:gosec // bounded above
	}
	return 0, false
}

// MayRepeat says whether an option legitimately appears more than once.
//
// The identity associations do: a client may ask for several addresses and
// several prefixes, each its own IA with its own identifier. Everything else
// appearing twice is a message two readers will disagree about.
func MayRepeat(code uint16) bool {
	switch code {
	case OptionIANA, OptionIATA, OptionIAPD, OptionIAAddr, OptionIAPrefix,
		OptionVendorClass, OptionVendorOpts, OptionStatusCode:
		return true
	}
	return false
}

// DangerousOptions are the options in a server's reply that configure something
// other than the client's own address.
//
// Each is an option some estate needs and a takeover in the others, which is why
// the default is to strip them from a reply and forward the rest: a client that
// still gets its address and no longer gets a resolver it should not have is a
// client that works.
//
// The list is longer than DHCPv4's, and two entries are worth saying out loud.
// The S46 containers put a host's *IPv4* traffic through a border relay of the
// sender's choosing -- a takeover of a protocol this message is not about. And
// the Server Unicast option tells the client to stop using the relay, which
// turns off every policy the relay has.
var DangerousOptions = []uint16{
	OptionDNSServers,
	OptionDomainList,
	OptionBootFileURL,
	OptionBootFileParam,
	OptionCaptivePortal,
	OptionSZTPRedirect,
	OptionAFTRName,
	OptionPCPServer,
	OptionDHCP4oDHCP6,
	OptionS46ContMAPE,
	OptionS46ContMAPT,
	OptionS46ContLW,
	OptionS46RuleV4V6,
	OptionUnicast,
	OptionVendorOpts,
	OptionSIPServerA,
	OptionSIPServerD,
	OptionNTPServer,
	OptionSNTPServers,
	OptionNISServers,
	OptionNISPServers,
}

// RelayOptions are the options a relay agent adds and a client has no business
// sending.
//
// RFC 4649 s3 and RFC 4580 s2 both say these are the relay's statement about
// which circuit and which subscriber a message came from. One arriving from a
// client is the client claiming to be somewhere it is not, which is the DHCPv6
// shape of the option 82 rule.
var RelayOptions = []uint16{OptionInterfaceID, OptionRemoteID, OptionSubscriberID}

// DUIDType is the form of a DHCP Unique Identifier.
type DUIDType uint16

// The DUID types of RFC 8415 s11 and RFC 6355.
const (
	DUIDLLT  DUIDType = 1 // link-layer address plus time
	DUIDEN   DUIDType = 2 // vendor-assigned, by enterprise number
	DUIDLL   DUIDType = 3 // link-layer address
	DUIDUUID DUIDType = 4 // RFC 6355: a machine's UUID
)

func (t DUIDType) String() string {
	switch t {
	case DUIDLLT:
		return "llt"
	case DUIDEN:
		return "en"
	case DUIDLL:
		return "ll"
	case DUIDUUID:
		return "uuid"
	}
	return fmt.Sprintf("duid(%d)", uint16(t))
}

// DUID is a parsed client or server identifier.
//
// Nothing authenticates it: a client chooses its own and a server takes it. What
// it is good for is naming the same device twice -- across reboots, across
// interfaces, and (for the link-layer forms) as the same device an inventory
// knows from DHCPv4, because the MAC address is inside it.
type DUID struct {
	Type DUIDType
	// Raw is the whole identifier as it arrived, which is what a lease is
	// keyed on and what a log line should carry.
	Raw []byte
	// Hardware and LinkLayer are the link-layer forms' contents: the ARP
	// hardware type and the address itself.
	Hardware  uint16
	LinkLayer []byte
	// Time is DUID-LLT's: seconds since 2000-01-01, from when the identifier
	// was generated. It is a client's own claim and worth nothing as a clock.
	Time uint32
	// Enterprise and ID are DUID-EN's.
	Enterprise uint32
	ID         []byte
	// UUID is DUID-UUID's sixteen octets.
	UUID []byte
}

// ParseDUID reads an identifier.
//
// A type this does not know is not an error: RFC 8415 s11.1 says a DUID is
// opaque and a receiver must treat an unknown type as an opaque identifier
// rather than refuse it. So the raw octets are kept and the fields are left
// empty, and a policy that wanted to insist on a known form can ask.
func ParseDUID(b []byte) (DUID, error) {
	if len(b) < 2 {
		return DUID{}, fmt.Errorf("%w: %d octets", ErrDUID, len(b))
	}
	if len(b) > MaxDUID {
		return DUID{}, fmt.Errorf("%w: %d octets, past the %d of RFC 8415", ErrDUID, len(b), MaxDUID)
	}
	d := DUID{Type: DUIDType(binary.BigEndian.Uint16(b)), Raw: b}
	body := b[2:]
	switch d.Type {
	case DUIDLLT:
		if len(body) < 6 {
			return DUID{}, fmt.Errorf("%w: a link-layer-and-time DUID of %d octets", ErrDUID, len(b))
		}
		d.Hardware = binary.BigEndian.Uint16(body)
		d.Time = binary.BigEndian.Uint32(body[2:])
		d.LinkLayer = body[6:]
	case DUIDLL:
		if len(body) < 2 {
			return DUID{}, fmt.Errorf("%w: a link-layer DUID of %d octets", ErrDUID, len(b))
		}
		d.Hardware = binary.BigEndian.Uint16(body)
		d.LinkLayer = body[2:]
	case DUIDEN:
		if len(body) < 4 {
			return DUID{}, fmt.Errorf("%w: an enterprise DUID of %d octets", ErrDUID, len(b))
		}
		d.Enterprise = binary.BigEndian.Uint32(body)
		d.ID = body[4:]
	case DUIDUUID:
		if len(body) != 16 {
			return DUID{}, fmt.Errorf("%w: a UUID DUID of %d octets", ErrDUID, len(body))
		}
		d.UUID = body
	}
	return d, nil
}

// String is a stable rendering: the type and the hexadecimal octets. It is what
// a lease table is keyed on and what a log line carries, so it must not change
// with what a client put inside.
func (d DUID) String() string {
	if len(d.Raw) == 0 {
		return "duid:none"
	}
	return d.Type.String() + ":" + hex.EncodeToString(d.Raw)
}

// HardwareAddr is the MAC address inside a link-layer DUID, in the usual
// notation, or "" for a form that has none.
//
// It is the one thing that ties a DHCPv6 client to the same machine's DHCPv4
// self, which is what an inventory built from both wants.
func (d DUID) HardwareAddr() string {
	if d.Type != DUIDLL && d.Type != DUIDLLT {
		return ""
	}
	if len(d.LinkLayer) == 0 || len(d.LinkLayer) > 20 {
		return ""
	}
	var b strings.Builder
	for i, c := range d.LinkLayer {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex.EncodeToString([]byte{c}))
	}
	return b.String()
}

// Status is a status code option's contents.
type Status struct {
	Code    uint16
	Message string
}

// The status codes of RFC 8415 s21.13 that a relay reports on.
const (
	StatusSuccess       uint16 = 0
	StatusUnspecFail    uint16 = 1
	StatusNoAddrsAvail  uint16 = 2
	StatusNoBinding     uint16 = 3
	StatusNotOnLink     uint16 = 4
	StatusUseMulticast  uint16 = 5
	StatusNoPrefixAvail uint16 = 6
)

var statusNames = map[uint16]string{
	StatusSuccess: "success", StatusUnspecFail: "unspecified_failure",
	StatusNoAddrsAvail: "no_addresses_available", StatusNoBinding: "no_binding",
	StatusNotOnLink: "not_on_link", StatusUseMulticast: "use_multicast",
	StatusNoPrefixAvail: "no_prefix_available",
}

// StatusName is a status code's name.
func StatusName(code uint16) string {
	if s, ok := statusNames[code]; ok {
		return s
	}
	return "status_" + strconv.Itoa(int(code))
}

// ParseStatus reads a status code option. The text is a server's, so it is not
// rendered anywhere a control sequence could act.
func ParseStatus(v []byte) (Status, error) {
	if len(v) < 2 {
		return Status{}, fmt.Errorf("%w: a status code of %d octets", ErrOption, len(v))
	}
	return Status{Code: binary.BigEndian.Uint16(v), Message: string(v[2:])}, nil
}

// IAAddr is an address inside an identity association, with its lifetimes.
type IAAddr struct {
	Addr netip.Addr
	// Preferred and Valid are the lifetimes in seconds. A valid lifetime of
	// zero is how a server withdraws an address.
	Preferred, Valid uint32
}

// IAPrefix is a delegated prefix, with its lifetimes.
//
// This is the option with no DHCPv4 equivalent, and the one worth bounding: a
// reply that delegates ::/0 has handed the client the whole of IPv6 to route,
// and a request that asks for a /48 where the estate delegates /56s is a client
// asking for sixteen times what it should have.
type IAPrefix struct {
	Prefix           netip.Prefix
	Preferred, Valid uint32
}

// IA is one identity association: an address association (IA_NA or IA_TA) or a
// prefix delegation (IA_PD).
type IA struct {
	// Code is which kind: OptionIANA, OptionIATA or OptionIAPD.
	Code uint16
	// IAID is the client's identifier for this association.
	IAID uint32
	// T1 and T2 are the renew and rebind times. An IA_TA has neither, which is
	// why they are zero there rather than absent.
	T1, T2 uint32
	// Addresses and Prefixes are what the association carries.
	Addresses []IAAddr
	Prefixes  []IAPrefix
	// Status is the association's own status code, when it has one: this is
	// where "no addresses available" and "no prefix available" live.
	Status *Status
}

// IAs reads every identity association in a message.
//
// The inner options of an IA are options, with the same length fields and the
// same need to be checked. A reader that walked them on trust would be walking
// a sender's arithmetic.
func (m *Message) IAs() ([]IA, error) {
	out := make([]IA, 0, 2)
	for _, o := range m.Options {
		switch o.Code {
		case OptionIANA, OptionIAPD:
			ia, err := parseIA(o.Code, o.Value, true)
			if err != nil {
				return nil, err
			}
			out = append(out, ia)
		case OptionIATA:
			ia, err := parseIA(o.Code, o.Value, false)
			if err != nil {
				return nil, err
			}
			out = append(out, ia)
		}
	}
	return out, nil
}

// parseIA reads one association. times says whether the header carries T1 and
// T2, which IA_NA and IA_PD have and IA_TA does not.
func parseIA(code uint16, v []byte, times bool) (IA, error) {
	head := 4
	if times {
		head = 12
	}
	if len(v) < head {
		return IA{}, fmt.Errorf("%w: %s of %d octets", ErrOption, OptionName(code), len(v))
	}
	ia := IA{Code: code, IAID: binary.BigEndian.Uint32(v)}
	if times {
		ia.T1 = binary.BigEndian.Uint32(v[4:])
		ia.T2 = binary.BigEndian.Uint32(v[8:])
	}
	inner, err := parseOptions(v[head:])
	if err != nil {
		return IA{}, err
	}
	for _, o := range inner {
		switch o.Code {
		case OptionIAAddr:
			a, err := parseIAAddr(o.Value)
			if err != nil {
				return IA{}, err
			}
			ia.Addresses = append(ia.Addresses, a)
		case OptionIAPrefix:
			p, err := parseIAPrefix(o.Value)
			if err != nil {
				return IA{}, err
			}
			ia.Prefixes = append(ia.Prefixes, p)
		case OptionStatusCode:
			st, err := ParseStatus(o.Value)
			if err != nil {
				return IA{}, err
			}
			ia.Status = &st
		}
	}
	return ia, nil
}

func parseIAAddr(v []byte) (IAAddr, error) {
	if len(v) < 24 {
		return IAAddr{}, fmt.Errorf("%w: an address option of %d octets", ErrOption, len(v))
	}
	return IAAddr{
		Addr:      addr16(v[:16]),
		Preferred: binary.BigEndian.Uint32(v[16:]),
		Valid:     binary.BigEndian.Uint32(v[20:]),
	}, nil
}

func parseIAPrefix(v []byte) (IAPrefix, error) {
	if len(v) < 25 {
		return IAPrefix{}, fmt.Errorf("%w: a prefix option of %d octets", ErrOption, len(v))
	}
	bits := int(v[8])
	if bits > 128 {
		return IAPrefix{}, fmt.Errorf("%w: a prefix length of %d", ErrOption, bits)
	}
	return IAPrefix{
		Prefix:    netip.PrefixFrom(addr16(v[9:25]), bits),
		Preferred: binary.BigEndian.Uint32(v[:4]),
		Valid:     binary.BigEndian.Uint32(v[4:8]),
	}, nil
}

// Addresses reads an option whose value is a list of IPv6 addresses, which is
// the shape of the DNS server, SNTP server, NTP-adjacent and NIS options.
func Addresses(v []byte) ([]netip.Addr, error) {
	if len(v)%16 != 0 {
		return nil, fmt.Errorf("%w: %d octets is not a list of addresses", ErrOption, len(v))
	}
	out := make([]netip.Addr, 0, len(v)/16)
	for i := 0; i < len(v); i += 16 {
		out = append(out, addr16(v[i:i+16]))
	}
	return out, nil
}

// Seconds reads a four-octet time.
func Seconds(v []byte) (uint32, error) {
	if len(v) != 4 {
		return 0, fmt.Errorf("%w: %d octets where four seconds belong", ErrOption, len(v))
	}
	return binary.BigEndian.Uint32(v), nil
}

// DomainNames reads a list of names in the wire format RFC 1035 s3.1 defines,
// which is what the domain search list and the AFTR name carry.
//
// The length octets are a sender's arithmetic and compression pointers are not
// allowed here, so both are checked: a name list a relay read differently from
// the client would be a search list nobody could account for.
func DomainNames(v []byte) ([]string, error) {
	out := make([]string, 0, 4)
	for len(v) > 0 {
		var name strings.Builder
		for {
			if len(v) == 0 {
				return nil, fmt.Errorf("%w: a name that does not end", ErrOption)
			}
			n := int(v[0])
			if n == 0 {
				v = v[1:]
				break
			}
			if n&0xc0 != 0 {
				// A compression pointer. RFC 8415 s10 has nowhere for one to
				// point, so this is a name two readers would disagree about.
				return nil, fmt.Errorf("%w: a compressed name", ErrOption)
			}
			if len(v) < 1+n {
				return nil, fmt.Errorf("%w: a label of %d octets with %d left", ErrOption, n, len(v)-1)
			}
			if name.Len() > 0 {
				name.WriteByte('.')
			}
			name.Write(v[1 : 1+n])
			v = v[1+n:]
		}
		if name.Len() > 0 {
			out = append(out, name.String())
		}
	}
	return out, nil
}
