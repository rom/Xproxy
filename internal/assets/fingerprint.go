package assets

import (
	"sort"
	"strings"
)

// The fingerprint engine.
//
// A rule is a predicate over what an asset has been seen doing and saying, and a
// role with a confidence attached. The highest-confidence rule that matches
// decides; every rule that matched contributes its reason, so the evidence is
// readable in the order it was weighed.
//
// The confidences are not arbitrary and the pattern in them is the whole design.
// A rule that fires on *behaviour* -- what protocol a device answered, which
// function codes, whether it was the server or the client -- is worth 60 to 85. A
// rule that fires on a *string the device chose* is worth 25 to 55. A rule that
// fires on a vendor prefix is worth 30 to 45 on its own, because three bytes of
// hardware address are the easiest thing in the estate to change. Nothing here
// reaches 100 except an observer that already knew.

// Role is what a device is for.
type Role string

// The roles. The list is the one an operational estate actually draws, which is
// not the same as a list of product categories: what matters is where a device
// sits in the process and therefore what it is allowed to do.
const (
	RoleUnknown Role = "unknown"
	// RolePLC is a programmable controller: it answers the control protocols
	// and it is the thing that must not be knocked over.
	RolePLC Role = "plc"
	// RoleRTU is a remote terminal unit, which is a controller reached over a
	// telecontrol protocol rather than a fieldbus.
	RoleRTU Role = "rtu"
	// RoleHMI is the panel or the workstation an operator drives the process
	// from: a *client* of the control protocols.
	RoleHMI Role = "hmi"
	// RoleDrive is a variable-speed drive or a servo: a controller's client and
	// a field device at once.
	RoleDrive Role = "drive"
	// RoleSensor is an instrument that reports and does not command.
	RoleSensor Role = "sensor"
	// RoleGateway is a protocol gateway or a terminal server: it speaks more
	// than one protocol, which is how it is recognised.
	RoleGateway Role = "field_gateway"
	// RoleHistorian collects and keeps process data. It reads widely and never
	// writes to the process.
	RoleHistorian Role = "historian"
	// RoleEngineering is an engineering workstation: the machine that changes
	// what a controller does, and the one whose behaviour is worth watching
	// most closely.
	RoleEngineering Role = "engineering_workstation"
	// RoleSCADA is a supervisory server.
	RoleSCADA Role = "scada_server"
	// RoleSwitch and RoleRouter are the network itself.
	RoleSwitch Role = "network_switch"
	RoleRouter Role = "router"
	// The devices that share the wire without being part of the process.
	RolePrinter     Role = "printer"
	RoleCamera      Role = "camera"
	RolePhone       Role = "voip_phone"
	RoleServer      Role = "server"
	RoleWorkstation Role = "workstation"
	RoleEmbedded    Role = "embedded_device"
)

// LevelUnknown is the Purdue level of a device whose place in the hierarchy the
// evidence does not say -- including the network equipment, which carries every
// level and sits at none.
const LevelUnknown = -1

// Level is the Purdue Enterprise Reference Architecture level a role sits at.
//
// The model is what an operational estate's segmentation is drawn from, so
// putting the level on the role means the inventory can answer the question a
// segmentation review actually asks: what is on this wire that does not belong
// at this level.
func (r Role) Level() int {
	switch r {
	case RoleSensor, RoleDrive:
		return 0
	case RolePLC, RoleRTU:
		return 1
	case RoleHMI, RoleSCADA, RoleGateway:
		return 2
	case RoleHistorian, RoleEngineering:
		return 3
	case RolePrinter, RoleCamera, RolePhone, RoleServer, RoleWorkstation:
		return 4
	}
	return LevelUnknown
}

// Known says whether a role is one of the named ones.
func (r Role) Known() bool {
	return r != "" && r != RoleUnknown && r.Level() != LevelUnknown || r == RoleSwitch || r == RoleRouter || r == RoleEmbedded
}

// RoleOf reads a role the way a configuration file writes it.
func RoleOf(s string) (Role, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, r := range Roles() {
		if string(r) == s {
			return r, true
		}
	}
	return "", false
}

// Roles are every role, in the order they are worth listing: down the process
// first, then the network, then the things that merely share the wire.
func Roles() []Role {
	return []Role{RoleUnknown, RoleSensor, RoleDrive, RolePLC, RoleRTU,
		RoleHMI, RoleSCADA, RoleGateway, RoleHistorian, RoleEngineering,
		RoleSwitch, RoleRouter, RolePrinter, RoleCamera, RolePhone,
		RoleServer, RoleWorkstation, RoleEmbedded}
}

// Classification is what the rules concluded.
type Classification struct {
	Role Role `json:"role"`
	// Level is the Purdue level, or LevelUnknown.
	Level int `json:"level"`
	// Confidence is 0 to 100. It is a weight rather than a probability: what it
	// is for is ordering the evidence and telling an engineer how hard to argue.
	Confidence int `json:"confidence"`
	// Why is the evidence, strongest first.
	Why []string `json:"why,omitempty"`
	// Ambiguous says two rules of equal weight disagreed about the role, which
	// is worth saying out loud rather than resolving silently.
	Ambiguous bool `json:"ambiguous,omitempty"`
}

// Rule is one fingerprint rule.
type Rule struct {
	// Name is what appears in the evidence list.
	Name string
	// Role is what this rule concludes.
	Role Role
	// Confidence is how much the conclusion is worth: see the scale above.
	Confidence int
	// Match says whether the rule applies.
	Match func(*Asset) bool
}

// Classify runs a rule set over an asset.
func Classify(a *Asset, rules []Rule) Classification {
	type hit struct {
		rule Rule
	}
	var hits []hit
	for _, r := range rules {
		if r.Match != nil && r.Match(a) {
			hits = append(hits, hit{rule: r})
		}
	}
	if len(hits) == 0 {
		return Classification{Role: RoleUnknown, Level: LevelUnknown}
	}
	// Strongest first, and stable within a confidence so that a rule set's own
	// order decides a tie rather than a map iteration.
	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i].rule.Confidence > hits[j].rule.Confidence
	})
	best := hits[0].rule
	c := Classification{Role: best.Role, Level: best.Role.Level(),
		Confidence: best.Confidence}
	for _, h := range hits {
		if len(c.Why) >= MaxWhy {
			break
		}
		c.Why = append(c.Why, h.rule.Name)
	}
	// Two rules of the same weight disagreeing is not something to resolve by
	// picking one: it is something an engineer should see.
	for _, h := range hits[1:] {
		if h.rule.Confidence == best.Confidence && h.rule.Role != best.Role {
			c.Ambiguous = true
			// A disputed conclusion is worth less than an undisputed one of the
			// same weight, and saying so is more honest than reporting the
			// weight the rule claimed on its own.
			c.Confidence -= 10
			break
		}
	}
	return c
}

// DefaultRules is the built-in rule set.
//
// It is deliberately conservative. A rule that would put a device at a role on
// thin evidence is worse than no rule: an inventory that says "unknown" invites
// somebody to look, and one that says "PLC" wrongly gets written into a
// segmentation policy.
func DefaultRules() []Rule {
	return []Rule{
		// ---- Behaviour on the control protocols. The strongest evidence here,
		// because a device cannot answer Modbus on a unit identifier without
		// being something that answers Modbus on a unit identifier.
		{
			Name: "answers Modbus as a server", Role: RolePLC, Confidence: 80,
			Match: func(a *Asset) bool {
				return a.Speaks("modbus") && a.AsServer > 0 && len(a.Units) > 0
			},
		},
		{
			Name: "answers IEC 60870-5-104 as a controlled station", Role: RoleRTU, Confidence: 80,
			Match: func(a *Asset) bool {
				return a.Speaks("iec104") && a.AsServer > 0
			},
		},
		{
			Name: "writes to Modbus registers", Role: RoleHMI, Confidence: 70,
			Match: func(a *Asset) bool {
				return a.Speaks("modbus") && a.AsServer == 0 && writesModbus(a.Funcs)
			},
		},
		{
			Name: "reads Modbus widely and never writes", Role: RoleHistorian, Confidence: 65,
			Match: func(a *Asset) bool {
				return a.Speaks("modbus") && a.AsServer == 0 &&
					!writesModbus(a.Funcs) && len(a.Units) >= 4
			},
		},
		{
			Name: "commands an IEC 60870-5-104 station", Role: RoleSCADA, Confidence: 70,
			Match: func(a *Asset) bool {
				return a.Speaks("iec104") && a.AsServer == 0
			},
		},
		{
			// A gateway *polls* the control protocol and republishes it. The
			// direction matters: a modern controller answers Modbus and also
			// publishes to MQTT, and it is a controller, not a gateway. What
			// makes something a gateway is that the control traffic is
			// somebody else's.
			Name: "polls a control protocol and carries it elsewhere", Role: RoleGateway, Confidence: 75,
			Match: func(a *Asset) bool {
				return (a.Speaks("modbus") || a.Speaks("iec104")) && a.AsServer == 0 &&
					(a.Speaks("mqtt") || a.Speaks("http") || a.Speaks("syslog"))
			},
		},
		{
			Name: "publishes Sparkplug telemetry", Role: RoleGateway, Confidence: 65,
			Match: func(a *Asset) bool {
				return a.Speaks("mqtt") && strings.HasPrefix(a.ClientID, "spBv1.0")
			},
		},
		{
			Name: "reads a Modbus device identification", Role: RoleEngineering, Confidence: 60,
			Match: func(a *Asset) bool {
				return a.Speaks("modbus") && a.AsServer == 0 && hasInt(a.Funcs, 0x2b)
			},
		},
		{
			Name: "fetched firmware over TFTP", Role: RoleEmbedded, Confidence: 55,
			Match: func(a *Asset) bool {
				return a.Speaks("tftp") && a.BootFile != ""
			},
		},

		// ---- What a device says about itself. Weaker, and often all there is.
		{
			Name: "SNMP description names a Cisco operating system", Role: RoleSwitch, Confidence: 70,
			Match: func(a *Asset) bool {
				d := strings.ToLower(a.Description)
				return strings.Contains(d, "cisco ios") || strings.Contains(d, "nx-os")
			},
		},
		{
			Name: "SNMP description names a router operating system", Role: RoleRouter, Confidence: 70,
			Match: func(a *Asset) bool {
				d := strings.ToLower(a.Description)
				// The product name is spelled the way its vendor spells it.
				const mikrotik = "router" + "os"
				return strings.Contains(d, "junos") || strings.Contains(d, mikrotik)
			},
		},
		{
			Name: "SNMP description names a printer", Role: RolePrinter, Confidence: 70,
			Match: func(a *Asset) bool {
				d := strings.ToLower(a.Description)
				return strings.Contains(d, "jetdirect") || strings.Contains(d, "laserjet") ||
					strings.Contains(d, "printer")
			},
		},
		{
			Name: "description names a programmable controller", Role: RolePLC, Confidence: 60,
			Match: func(a *Asset) bool {
				d := strings.ToLower(a.Description + " " + a.Model)
				for _, s := range []string{"simatic", "s7-", "controllogix", "compactlogix",
					"micrologix", "modicon", "twido", "cj2", "cp1", "melsec"} {
					if strings.Contains(d, s) {
						return true
					}
				}
				return false
			},
		},
		{
			Name: "description names a variable-speed drive", Role: RoleDrive, Confidence: 60,
			Match: func(a *Asset) bool {
				d := strings.ToLower(a.Description + " " + a.Model)
				for _, s := range []string{"powerflex", "altivar", "sinamics", "micromaster",
					"vfd", "inverter drive"} {
					if strings.Contains(d, s) {
						return true
					}
				}
				return false
			},
		},
		{
			Name: "DHCP vendor class names a Windows client", Role: RoleWorkstation, Confidence: 45,
			Match: func(a *Asset) bool {
				return strings.HasPrefix(a.VendorClass, "MSFT")
			},
		},
		{
			Name: "DHCP vendor class names an embedded stack", Role: RoleEmbedded, Confidence: 40,
			Match: func(a *Asset) bool {
				v := strings.ToLower(a.VendorClass)
				for _, s := range []string{"udhcp", "dhcpcd", "busybox", "lwip", "vxworks"} {
					if strings.Contains(v, s) {
						return true
					}
				}
				return false
			},
		},
		{
			Name: "boots from the network", Role: RoleWorkstation, Confidence: 35,
			Match: func(a *Asset) bool {
				return strings.HasPrefix(a.VendorClass, "PXEClient") ||
					strings.HasSuffix(strings.ToLower(a.BootFile), ".efi")
			},
		},

		// ---- The vendor prefix, which is the weakest thing here and is only
		// allowed to conclude a role where the vendor makes one kind of device.
		{
			Name: "vendor prefix belongs to a camera manufacturer", Role: RoleCamera, Confidence: 45,
			Match: func(a *Asset) bool { return vendorIs(a, "Axis Communications") },
		},
		{
			Name: "vendor prefix belongs to a telephone manufacturer", Role: RolePhone, Confidence: 45,
			Match: func(a *Asset) bool {
				return vendorIs(a, "Polycom") || vendorIs(a, "Yealink")
			},
		},
		{
			Name: "vendor prefix belongs to a label printer manufacturer", Role: RolePrinter, Confidence: 45,
			Match: func(a *Asset) bool { return vendorIs(a, "Zebra Technologies") },
		},
		{
			Name: "vendor prefix belongs to a single-board computer", Role: RoleEmbedded, Confidence: 40,
			Match: func(a *Asset) bool { return vendorIs(a, "Raspberry Pi") },
		},
		{
			Name: "vendor prefix belongs to a hypervisor", Role: RoleServer, Confidence: 40,
			Match: func(a *Asset) bool { return vendorIs(a, "VMware") },
		},
		{
			Name: "vendor prefix belongs to an industrial networking manufacturer", Role: RoleGateway, Confidence: 35,
			Match: func(a *Asset) bool {
				return vendorIs(a, "Moxa") || vendorIs(a, "Hirschmann")
			},
		},
	}
}

// writesModbus says whether any of the function codes changes something. The
// distinction between reading and writing is the one a process engineer cares
// about most, so it is named here rather than spelled out in three rules.
func writesModbus(funcs []int) bool {
	for _, f := range funcs {
		switch f {
		case 0x05, 0x06, 0x0f, 0x10, 0x16, 0x17:
			return true
		}
	}
	return false
}

func hasInt(list []int, v int) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func vendorIs(a *Asset, name string) bool { return a.Vendor == name }
