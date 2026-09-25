package dhcp

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The option codes of RFC 2132 and the later documents, with the ones that
// carry a *configuration* rather than a value named and commented -- because
// those are the ones a policy is about. The full list is IANA's; a code this
// package does not name is still read, carried and refusable by number.
const (
	OptPad uint8 = 0
	// OptSubnetMask, OptRouter and OptDNS are the three that decide where a
	// machine's traffic goes. A wrong router is an interception; a wrong
	// resolver is every name the machine looks up.
	OptSubnetMask uint8 = 1
	OptRouter     uint8 = 3
	OptDNS        uint8 = 6
	OptHostname   uint8 = 12
	// OptBootFileSize and OptRootPath belong to the machines that boot from
	// the network, which is where a wrong answer becomes code execution.
	OptBootFileSize uint8 = 13
	OptDomainName   uint8 = 15
	OptInterfaceMTU uint8 = 26
	// OptBroadcast, OptStaticRoute (the obsolete one), OptNTPServers and
	// OptVendorSpecific.
	OptBroadcast   uint8 = 28
	OptStaticRoute uint8 = 33
	OptNTPServers  uint8 = 42
	// OptVendorSpecific is option 43, which is whatever a vendor decided and
	// is how PXE carries most of what it does.
	OptVendorSpecific uint8 = 43
	OptNetBIOSNS      uint8 = 44
	OptNetBIOSScope   uint8 = 47
	OptRequestedIP    uint8 = 50
	OptLeaseTime      uint8 = 51
	// OptOverload is option 52: the one that says the header's own string
	// fields carry options.
	OptOverload    uint8 = 52
	OptMessageType uint8 = 53
	OptServerID    uint8 = 54
	// OptParameterList is option 55: what the client is asking to be told.
	// It is worth a policy of its own, because a client asking for option 252
	// is a client that will use a proxy if something offers one.
	OptParameterList uint8 = 55
	OptMessage       uint8 = 56
	OptMaxMessage    uint8 = 57
	OptRenewalTime   uint8 = 58
	OptRebindTime    uint8 = 59
	OptVendorClass   uint8 = 60
	// OptClientID is option 61. It is what a client says it is, and a lease
	// is keyed on it where it is present -- so a client whose option 61
	// disagrees with its own chaddr is worth noticing.
	OptClientID uint8 = 61
	// OptTFTPServer and OptBootFile are 66 and 67: where a machine boots from
	// and what it boots. On a network with PXE clients these two are the most
	// dangerous options in the protocol.
	OptTFTPServer uint8 = 66
	OptBootFile   uint8 = 67
	OptUserClass  uint8 = 77
	// OptRapidCommit is RFC 4039: a zero-length option whose presence is the
	// whole message. It is here as the named example of that shape, because an
	// encoder that dropped a valueless option would be changing what the
	// message says.
	OptRapidCommit uint8 = 80
	// OptClientFQDN is RFC 4702: the name a client asks the server to
	// register in DNS on its behalf.
	OptClientFQDN uint8 = 81
	// OptRelayAgent is RFC 3046 option 82, the relay agent information
	// option. A *client* must never send it: RFC 3046 §2.1 says a relay
	// discards a message that arrives from a client carrying one, because the
	// whole point of the option is that the relay -- not the client -- says
	// which circuit the client is on.
	OptRelayAgent uint8 = 82
	// OptArchitecture, OptNetworkInterface and OptMachineID are RFC 4578's
	// PXE options: what kind of machine is booting.
	OptArchitecture     uint8 = 93
	OptNetworkInterface uint8 = 94
	OptMachineID        uint8 = 97
	// OptDomainSearch is RFC 3397.
	OptDomainSearch uint8 = 119
	// OptClasslessRoute is RFC 3442 option 121, and OptMSClasslessRoute is
	// Microsoft's 249, which carries the same thing because Windows shipped
	// before the number was assigned. Either one is a routing table in a
	// broadcast reply, and an estate that does not use them should refuse
	// them: this is the single most direct interception in the protocol.
	OptClasslessRoute   uint8 = 121
	OptMSClasslessRoute uint8 = 249
	// OptWPAD is option 252, the proxy auto-discovery URL. A machine that
	// takes it sends its web traffic wherever the URL says.
	OptWPAD uint8 = 252
	OptEnd  uint8 = 255
)

var optionNames = map[uint8]string{
	OptPad: "pad", OptSubnetMask: "subnet_mask", OptRouter: "router",
	OptDNS: "dns_servers", OptHostname: "hostname",
	OptBootFileSize: "boot_file_size", OptDomainName: "domain_name",
	OptInterfaceMTU: "interface_mtu", OptBroadcast: "broadcast_address",
	OptStaticRoute: "static_route", OptNTPServers: "ntp_servers",
	OptVendorSpecific: "vendor_specific", OptNetBIOSNS: "netbios_name_servers",
	OptNetBIOSScope: "netbios_scope", OptRequestedIP: "requested_address",
	OptLeaseTime: "lease_time", OptOverload: "option_overload",
	OptMessageType: "message_type", OptServerID: "server_identifier",
	OptParameterList: "parameter_list", OptMessage: "message",
	OptMaxMessage: "max_message_size", OptRenewalTime: "renewal_time",
	OptRebindTime: "rebind_time", OptVendorClass: "vendor_class",
	OptClientID: "client_identifier", OptTFTPServer: "tftp_server",
	OptBootFile: "boot_file", OptUserClass: "user_class",
	OptClientFQDN: "client_fqdn", OptRelayAgent: "relay_agent",
	OptArchitecture: "client_architecture", OptNetworkInterface: "network_interface",
	OptMachineID: "machine_identifier", OptDomainSearch: "domain_search",
	OptClasslessRoute:   "classless_static_route",
	OptMSClasslessRoute: "ms_classless_static_route",
	OptWPAD:             "wpad_url", OptEnd: "end",
}

// OptionName names an option for a log line an operator reads. A code nobody
// named is given as a number, because a number an operator can look up is
// better than a label this package invented.
func OptionName(code uint8) string {
	if n, ok := optionNames[code]; ok {
		return n
	}
	return "option_" + strconv.Itoa(int(code))
}

// OptionOf names an option the way a configuration file writes it: by name for
// the ones that have one, or by number for any of them. A number is always
// accepted, because an estate's own vendor option has no name here and
// refusing to let an operator name it would make the policy incomplete.
func OptionOf(s string) (uint8, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > 255 {
			return 0, false
		}
		return uint8(n), true
	}
	for code, name := range optionNames {
		if name == s {
			return code, true
		}
	}
	return 0, false
}

// DangerousOptions are the options that carry a machine's *configuration*
// rather than a value it displays: where its traffic goes, what it trusts and
// what it boots.
//
// It is the default deny list for a server's answer, and the list is short on
// purpose. Each entry is an option some estate legitimately needs -- which is
// why it is a default and not a rule -- and each is a takeover in an estate
// that does not: a route, a proxy, a boot image, or a vendor blob that is any
// of the three.
var DangerousOptions = []uint8{
	OptClasslessRoute, OptMSClasslessRoute, OptStaticRoute,
	OptWPAD, OptTFTPServer, OptBootFile, OptVendorSpecific,
}

// Addresses reads an option whose value is a list of IPv4 addresses, which is
// the shape of options 3, 6, 42 and 44. A length that is not a multiple of
// four is refused rather than rounded: a client would read it somehow, and
// "somehow" is where the two readings differ.
func Addresses(v []byte) ([]netip.Addr, error) {
	if len(v) == 0 || len(v)%4 != 0 {
		return nil, fmt.Errorf("%w: %d octets is not a list of addresses", ErrShape, len(v))
	}
	out := make([]netip.Addr, 0, len(v)/4)
	for i := 0; i < len(v); i += 4 {
		out = append(out, addr4(v[i:i+4]))
	}
	return out, nil
}

// Address reads an option whose value is one IPv4 address: options 1, 28, 50,
// 54, 66 when it is an address rather than a name.
func Address(v []byte) (netip.Addr, error) {
	if len(v) != 4 {
		return netip.Addr{}, fmt.Errorf("%w: %d octets is not an address", ErrShape, len(v))
	}
	return addr4(v), nil
}

// Seconds reads a four-octet duration: options 51, 58 and 59.
func Seconds(v []byte) (uint32, error) {
	if len(v) != 4 {
		return 0, fmt.Errorf("%w: %d octets is not a duration", ErrShape, len(v))
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3]), nil
}

// Route is one destination and gateway from option 121 or 249.
type Route struct {
	Dest    netip.Prefix
	Gateway netip.Addr
}

// Routes reads RFC 3442's classless static route option, which is the one
// option worth decoding rather than merely refusing: an operator who sees a
// refusal deserves to be told *which route* was being pushed at their
// machines, and an estate that legitimately uses the option needs its contents
// in the log.
//
// The encoding is deliberately compact -- a prefix length, then only the
// significant octets of the destination, then the gateway -- which is also
// what makes it easy to get wrong.
func Routes(v []byte) ([]Route, error) {
	var out []Route
	for i := 0; i < len(v); {
		width := int(v[i])
		if width > 32 {
			return nil, fmt.Errorf("%w: a prefix of %d bits", ErrShape, width)
		}
		i++
		sig := (width + 7) / 8
		if i+sig+4 > len(v) {
			return nil, fmt.Errorf("%w: a route that ends inside itself", ErrTruncated)
		}
		var dst [4]byte
		copy(dst[:], v[i:i+sig])
		i += sig
		gw := addr4(v[i : i+4])
		i += 4
		p, err := netip.AddrFrom4(dst).Prefix(width)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrShape, err)
		}
		out = append(out, Route{Dest: p, Gateway: gw})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no routes", ErrShape)
	}
	return out, nil
}

// String renders a route the way an operator reads one.
func (r Route) String() string { return r.Dest.String() + " via " + r.Gateway.String() }

// HardwareAddr renders a hardware address as the colon-separated hex an
// operator recognises, which is what a log line and a rule both use.
func HardwareAddr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&0xf])
	}
	return sb.String()
}

// ParseHardwareAddr reads the colon- or hyphen-separated hex a rule is written
// with. It is deliberately strict about the octet count and lenient about the
// separator, because the separator is a matter of which vendor's documentation
// somebody copied from.
func ParseHardwareAddr(s string) ([]byte, error) {
	f := strings.FieldsFunc(strings.TrimSpace(s), func(r rune) bool {
		return r == ':' || r == '-' || r == '.'
	})
	if len(f) == 0 || len(f) > MaxHWLen {
		return nil, fmt.Errorf("%w: %q is not a hardware address", ErrShape, s)
	}
	out := make([]byte, 0, len(f))
	for _, part := range f {
		if len(part) != 2 {
			return nil, fmt.Errorf("%w: %q is not a hardware address", ErrShape, s)
		}
		n, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not a hardware address", ErrShape, s)
		}
		out = append(out, byte(n))
	}
	return out, nil
}

// OUI is the first three octets of a hardware address: the vendor. It is what
// a policy written about "the telephones" is actually written about, because
// nobody lists every handset's address.
func OUI(b []byte) string {
	if len(b) < 3 {
		return ""
	}
	return HardwareAddr(b[:3])
}
