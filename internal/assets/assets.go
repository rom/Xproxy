// Package assets keeps an inventory of the devices a proxy has seen, and works
// out what each one is.
//
// An operational estate's oldest problem is that nobody knows what is on the
// network. The engineering drawings are out of date, the spreadsheet was
// abandoned, and the one thing nobody may do is run a scanner: an active scan
// is how a programmable controller gets knocked over, and on a safety network
// it is a thing people lose their jobs for. So the inventory has to be built
// from traffic that was going to happen anyway.
//
// A security proxy is an unusually good place to do that, because it already
// parses the protocols. The relay kinds read Modbus function codes, IEC 104
// common addresses, SNMP object identifiers, MQTT client identifiers, DHCP
// vendor classes and TFTP filenames -- and each of those says something about
// what sent it. This package is where those observations are collected, merged
// into one record per device, and turned into a guess about what the device is.
//
// Three things are deliberate.
//
// **Behaviour outweighs self-description.** A device's vendor class, its host
// name and its SNMP description are strings it chose, and a hardware address is
// three bytes of vendor prefix anybody can set. What a device *does* -- answering
// Modbus function 3 on unit 1, carrying IEC 104 interrogations, asking for a
// firmware image over TFTP -- is much harder to fake without becoming the thing
// it is pretending to be. So the rules that fire on behaviour carry more
// confidence than the rules that fire on a string, and every classification
// keeps the evidence that produced it.
//
// **A guess says how sure it is, and why.** An inventory that reports "PLC" with
// no confidence and no evidence is one an engineer cannot argue with, and being
// unable to argue with it is how a wrong entry survives for years. Every asset
// carries a confidence and the list of rules that matched, in order.
//
// **What changes is the finding.** A steady-state inventory is a reference
// document. The security value is in the deltas: a hardware address whose vendor
// prefix changed, an address that moved to a different hardware address, a
// device whose role changed, and -- once a baseline is frozen -- a device that
// was never there before. Those are what this package raises.
//
// What it does not do is scan, probe or connect to anything. Everything here is
// a by-product of traffic the proxy was already carrying.
package assets

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/textsafe"
)

// Bounds on what a device is allowed to tell us about itself. Every string here
// is peer-chosen, so each is clipped: an inventory is read by people, and a
// vendor class with a control sequence in it is a log injection with a user
// interface in front of it.
const (
	// MaxString bounds one self-reported value.
	MaxString = 96
	// MaxAddrs bounds the addresses one asset remembers. A device that has had
	// more than this many is a DHCP pool being churned, and the oldest are the
	// least interesting.
	MaxAddrs = 8
	// MaxChanges bounds the change log per asset.
	MaxChanges = 16
	// MaxProtos bounds the protocols one asset is recorded as speaking, which
	// cannot exceed the number of listener kinds but is bounded anyway.
	MaxProtos = 24
	// MaxWhy bounds the evidence list on a classification.
	MaxWhy = 8
	// DefaultMax is how many assets an inventory holds before the oldest goes.
	DefaultMax = 8192
	// DefaultTTL is how long an unseen asset is kept.
	DefaultTTL = 30 * 24 * time.Hour
)

// Observation is one thing a listener noticed about one device.
//
// Every field is optional: a Modbus listener knows an address and a unit
// identifier and nothing else, a DHCP listener knows a hardware address and
// half a dozen strings, and the inventory's job is to make one record out of
// both.
type Observation struct {
	At       time.Time
	Listener string
	// Proto is the protocol the device spoke, which is the listener's kind.
	Proto string
	// Addr and Hardware are the two ways a device is identified. A DHCP
	// listener has both; everything else has only the address, which is why
	// the inventory has to merge.
	Addr     netip.Addr
	Hardware []byte
	// Server says the device was acting as the *server* in this exchange,
	// which is most of what distinguishes a controller from the thing talking
	// to it: on Modbus the PLC answers and the HMI asks.
	Server bool

	// The strings a device says about itself. Weak evidence, kept because it
	// is often the only evidence, and clipped because it is peer-chosen.
	VendorClass string
	UserClass   string
	Hostname    string
	Description string
	ClientID    string
	BootFile    string
	UserAgent   string
	Model       string
	Firmware    string
	// Maker is the manufacturer a device named *itself* -- a Modbus
	// identification response's vendor name, an SNMP system description's
	// first field. It is a different claim from Vendor on the asset, which is
	// what a hardware prefix resolved to, and the two disagree often enough
	// that collapsing them would lose information: a prefix belongs to
	// whoever made the network module, and the device's own answer names
	// whoever made the device.
	Maker string

	// The shapes of what it asked for or answered, which are the stronger
	// evidence: a device cannot change these without changing what it does.
	Params  []uint8  // a DHCP parameter list, in the order it was sent
	Units   []int    // Modbus unit identifiers
	Objects []int    // IEC 104 common addresses
	Funcs   []int    // Modbus function codes
	OIDs    []string // SNMP object identifiers

	// Role is a classification the observer already knows, which is rare and
	// is trusted above the rules when it is set.
	Role Role
}

// Asset is one device, as the inventory understands it.
type Asset struct {
	// ID is stable for the life of the record: the hardware address when one
	// is known, otherwise the address. It is what an operator's own notes can
	// be keyed on, so it does not change when a device's address does.
	ID string `json:"id"`
	// Hardware is the device's hardware address, when a listener saw one.
	Hardware string `json:"hardware,omitempty"`
	// OUI and Vendor are the vendor prefix and what it resolves to. Weak
	// evidence -- three bytes anybody can set -- and useful anyway, because
	// most devices do not bother.
	OUI    string `json:"oui,omitempty"`
	Vendor string `json:"vendor,omitempty"`
	// Addrs are the addresses this device has been seen at, newest first.
	Addrs []string `json:"addresses,omitempty"`

	// What the device says about itself.
	Hostname    string `json:"hostname,omitempty"`
	VendorClass string `json:"vendor_class,omitempty"`
	UserClass   string `json:"user_class,omitempty"`
	Description string `json:"description,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	BootFile    string `json:"boot_file,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	Model       string `json:"model,omitempty"`
	Firmware    string `json:"firmware,omitempty"`
	// Maker is the manufacturer the device named itself, where a protocol let
	// it. Kept beside Vendor rather than folded into it: Vendor is a hardware
	// prefix resolved through a registry, this is the device's own answer, and
	// an advisory search wants the second one first.
	Maker string `json:"maker,omitempty"`

	// Protos counts the observations per protocol, which is how an operator
	// sees that a device speaks both Modbus and HTTP -- usually a gateway, and
	// occasionally a controller with a web interface nobody meant to expose.
	Protos map[string]uint64 `json:"protocols,omitempty"`
	// Listeners are the listeners that saw it, which is where it is.
	Listeners []string `json:"listeners,omitempty"`

	// Behaviour, accumulated. These are the fields the fingerprint rules weigh
	// most heavily.
	Units   []int    `json:"modbus_units,omitempty"`
	Objects []int    `json:"iec104_addresses,omitempty"`
	Funcs   []int    `json:"modbus_functions,omitempty"`
	OIDs    []string `json:"snmp_oids,omitempty"`
	// AsServer and AsClient count the exchanges in which this device answered
	// and in which it asked. On the industrial protocols that distinction is
	// most of the classification.
	AsServer uint64 `json:"as_server,omitempty"`
	AsClient uint64 `json:"as_client,omitempty"`

	Class Classification `json:"classification"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"observations"`
	// Changes is what makes this a security record rather than a reference
	// document: the identity of a device is not supposed to change.
	Changes []Change `json:"changes,omitempty"`
	// New says this asset was not in the frozen baseline, when there is one.
	New bool `json:"new,omitempty"`
}

// Change is one identity change on an asset.
type Change struct {
	At   time.Time `json:"at"`
	What string    `json:"what"`
	From string    `json:"from,omitempty"`
	To   string    `json:"to,omitempty"`
}

// The change kinds, which are the findings an inventory produces.
const (
	// ChangeVendor is an asset whose vendor prefix now resolves to a different
	// manufacturer, which happens when a vendor list is loaded or reloaded
	// under a running inventory rather than because a device changed.
	ChangeVendor = "vendor_changed"
	// ChangeRole is a device whose classification changed. A controller that
	// started behaving like an engineering station is the single most
	// interesting line an inventory can produce.
	ChangeRole = "role_changed"
	// ChangeAddr is a device that appeared at a new address, which is ordinary
	// on a DHCP segment and worth recording on a static one.
	ChangeAddr = "address_changed"
	// ChangeNew is an asset that was not in the frozen baseline.
	ChangeNew = "new_asset"
	// ChangeAddrTaken is an address that now belongs to a different device: a
	// hardware address nobody has seen, at an address another record already
	// holds. This is what a device swapped out under one address looks like,
	// and on a static estate it is also what somebody standing in for a device
	// that is switched off looks like.
	//
	// It is recorded on the record that *lost* the address, because the new
	// device gets a record of its own and the old one would otherwise simply
	// stop appearing -- and "stopped appearing" is not a finding anybody reads.
	ChangeAddrTaken = "address_taken"
)

// Inventory is the set of assets a proxy has seen.
//
// It is bounded and it expires, and the bound behaves differently from the
// pairing tables in the relay kinds: there, forgetting an entry makes a
// decision wrong, so a full table refuses. Here forgetting loses *history*, and
// refusing would mean the inventory stops noticing the estate at exactly the
// moment something is filling it up. So the least recently seen asset goes, and
// the count of what went is exported.
type Inventory struct {
	mu   sync.RWMutex
	byID map[string]*Asset
	// byHW and byAddr are the two ways in. An address that a DHCP lease has
	// bound to a hardware address resolves to the same asset through either.
	byHW   map[string]*Asset
	byAddr map[netip.Addr]*Asset

	max int
	ttl time.Duration
	now func() time.Time

	// vendors resolves a hardware prefix to a vendor name.
	vendors *Vendors
	// rules is the fingerprint rule set.
	rules []Rule

	// baseline, when set, is the identifiers that were in the estate when
	// somebody froze it. Anything else is new.
	baseline map[string]bool

	// Dropped counts the assets the bound evicted, and Refused the
	// observations that named nothing identifiable.
	Dropped  uint64
	Refused  uint64
	Expired  uint64
	Findings uint64

	// onChange is called for every change an observation produced, which is
	// how a security event gets written without this package knowing what a
	// log is.
	onChange func(*Asset, Change)
}

// Options configure an inventory.
type Options struct {
	// Max is how many assets to hold; zero means DefaultMax.
	Max int
	// TTL is how long an unseen asset is kept; zero means DefaultTTL.
	TTL time.Duration
	// Now is the clock, for tests.
	Now func() time.Time
	// Vendors resolves hardware prefixes. Nil uses the built-in seed list.
	Vendors *Vendors
	// Rules is the fingerprint rule set. Nil uses the built-in one.
	Rules []Rule
	// OnChange is called for each identity change. It runs on the observing
	// goroutine, so it must not block.
	OnChange func(*Asset, Change)
}

// New builds an inventory.
func New(o Options) *Inventory {
	inv := &Inventory{
		byID: map[string]*Asset{}, byHW: map[string]*Asset{},
		byAddr: map[netip.Addr]*Asset{},
		max:    o.Max, ttl: o.TTL, now: o.Now,
		vendors: o.Vendors, rules: o.Rules, onChange: o.OnChange,
	}
	if inv.max <= 0 {
		inv.max = DefaultMax
	}
	if inv.ttl <= 0 {
		inv.ttl = DefaultTTL
	}
	if inv.now == nil {
		inv.now = time.Now
	}
	if inv.vendors == nil {
		inv.vendors = SeedVendors()
	}
	if inv.rules == nil {
		inv.rules = DefaultRules()
	}
	return inv
}

// Observe records one observation and returns the asset it landed on, or nil
// when the observation named nothing that could identify a device.
func (inv *Inventory) Observe(o Observation) *Asset {
	if o.At.IsZero() {
		o.At = inv.now()
	}
	hw := normalHW(o.Hardware)
	if hw == "" && !o.Addr.IsValid() {
		// Nothing to key on. This is not a failure: a listener that saw a
		// malformed packet has an observation with no identity in it, and the
		// honest thing is to count it rather than invent an asset.
		inv.mu.Lock()
		inv.Refused++
		inv.mu.Unlock()
		return nil
	}
	if o.Addr.IsValid() && (o.Addr.IsUnspecified() || o.Addr.IsLoopback()) && hw == "" {
		// An address that identifies nothing: a booting client sends from
		// 0.0.0.0, and loopback is the proxy talking to itself.
		inv.mu.Lock()
		inv.Refused++
		inv.mu.Unlock()
		return nil
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.expire(o.At)
	a, changes := inv.merge(o, hw)
	if a == nil {
		return nil
	}
	inv.classify(a, o.At, &changes)
	inv.Findings += uint64(len(changes))
	a.Changes = appendBounded(a.Changes, changes, MaxChanges)
	if inv.onChange != nil {
		for _, c := range changes {
			inv.onChange(a, c)
		}
	}
	return a.clone()
}

// merge finds or creates the asset an observation belongs to and folds the
// observation into it.
func (inv *Inventory) merge(o Observation, hw string) (*Asset, []Change) {
	var changes []Change
	a, taken := inv.find(hw, o.Addr)
	if taken != nil {
		// The address is one another device's record holds, and this
		// observation carries a hardware address that record does not have. Two
		// devices, not one: an inventory whose records merged here would end up
		// with one entry describing two machines, and the older machine's
		// history -- its vendor, its role, what it was seen doing -- would be
		// silently overwritten by the newer one's.
		taken.Changes = appendBounded(taken.Changes, []Change{{At: o.At,
			What: ChangeAddrTaken, From: o.Addr.String(), To: hw}}, MaxChanges)
		inv.Findings++
		if inv.onChange != nil {
			inv.onChange(taken, taken.Changes[len(taken.Changes)-1])
		}
	}
	if a == nil {
		if len(inv.byID) >= inv.max && !inv.evict() {
			inv.Dropped++
			return nil, nil
		}
		id := hw
		if id == "" {
			id = o.Addr.String()
		}
		a = &Asset{ID: id, FirstSeen: o.At, Protos: map[string]uint64{},
			Class: Classification{Role: RoleUnknown, Level: LevelUnknown}}
		inv.byID[id] = a
		if inv.baseline != nil && !inv.baseline[id] {
			a.New = true
			changes = append(changes, Change{At: o.At, What: ChangeNew, To: id})
		}
	}
	if hw != "" {
		if a.Hardware == "" {
			// An asset first seen by address and now by hardware address keeps
			// its identifier: an operator's notes are keyed on it, and it is
			// the same device either way.
			a.Hardware = hw
			a.OUI = hw[:8]
			a.Vendor = inv.vendors.Lookup(o.Hardware)
		}
		// There is deliberately no branch for "this record has a different
		// hardware address". It cannot happen: a record that has one is only
		// ever found through the hardware index, which is keyed on the address
		// it holds. A device whose hardware address changes is a device this
		// package cannot recognise as the same one -- which is the point of
		// splitting the records -- and it shows up as a new asset plus an
		// address_taken note on the old one.
		inv.byHW[hw] = a
	}
	if o.Addr.IsValid() && !o.Addr.IsUnspecified() {
		s := o.Addr.String()
		if len(a.Addrs) == 0 {
			a.Addrs = []string{s}
		} else if a.Addrs[0] != s {
			changes = append(changes, Change{At: o.At, What: ChangeAddr,
				From: a.Addrs[0], To: s})
			a.Addrs = prependBounded(a.Addrs, s, MaxAddrs)
		}
		inv.byAddr[o.Addr] = a
	}
	// The self-reported strings. Each is kept the first time and on change,
	// clipped, and a later empty value never erases an earlier one: a Modbus
	// observation knowing no host name should not delete the one DHCP saw.
	setIf(&a.Hostname, o.Hostname)
	setIf(&a.VendorClass, o.VendorClass)
	setIf(&a.UserClass, o.UserClass)
	setIf(&a.Description, o.Description)
	setIf(&a.ClientID, o.ClientID)
	setIf(&a.BootFile, o.BootFile)
	setIf(&a.UserAgent, o.UserAgent)
	setIf(&a.Model, o.Model)
	setIf(&a.Firmware, o.Firmware)
	setIf(&a.Maker, o.Maker)

	if o.Proto != "" && len(a.Protos) < MaxProtos {
		a.Protos[o.Proto]++
	} else if o.Proto != "" {
		if _, known := a.Protos[o.Proto]; known {
			a.Protos[o.Proto]++
		}
	}
	if o.Listener != "" {
		a.Listeners = addSet(a.Listeners, o.Listener, MaxProtos)
	}
	a.Units = addInts(a.Units, o.Units)
	a.Objects = addInts(a.Objects, o.Objects)
	a.Funcs = addInts(a.Funcs, o.Funcs)
	for _, oid := range o.OIDs {
		a.OIDs = addSet(a.OIDs, oid, MaxProtos)
	}
	if o.Server {
		a.AsServer++
	} else {
		a.AsClient++
	}
	a.LastSeen = o.At
	a.Count++
	if o.Role != "" && o.Role != RoleUnknown {
		// An observer that already knows outranks the rules.
		a.Class = Classification{Role: o.Role, Level: o.Role.Level(),
			Confidence: 100, Why: []string{"the listener said so"}}
	}
	return a, changes
}

// find resolves an observation to an existing asset, and to the asset whose
// address this observation is taking over when it is doing that.
//
// The hardware address wins when both are known, because it is the identity that
// survives a lease. The interesting case is the third one: an observation
// carrying a hardware address nobody has, at an address another record already
// holds *with a hardware address of its own*. That is two devices sharing one
// address over time, and the records must not merge -- one entry describing two
// machines would overwrite the older machine's vendor, role and history with the
// newer machine's, which is exactly the history an incident needs.
//
// An existing record with no hardware address at all is the opposite case and
// does merge: that is a device seen first by a listener that knew only its
// address, and now by DHCP, which knows both.
func (inv *Inventory) find(hw string, addr netip.Addr) (found, taken *Asset) {
	if hw != "" {
		if a := inv.byHW[hw]; a != nil {
			return a, nil
		}
	}
	if addr.IsValid() {
		if a := inv.byAddr[addr]; a != nil {
			if hw == "" || a.Hardware == "" {
				return a, nil
			}
			return nil, a
		}
	}
	return nil, nil
}

// classify runs the fingerprint rules and records a role change.
func (inv *Inventory) classify(a *Asset, at time.Time, changes *[]Change) {
	if a.Class.Confidence == 100 && a.Class.Role != RoleUnknown {
		// Set by an observer that knows; the rules do not argue with it.
		return
	}
	c := Classify(a, inv.rules)
	if c.Role == a.Class.Role {
		a.Class = c
		return
	}
	if a.Class.Role != RoleUnknown && c.Role != RoleUnknown {
		// A device whose classification changed. Not merely new evidence
		// arriving -- a role it did not have before, which on a static estate
		// is the most interesting line in the inventory.
		*changes = append(*changes, Change{At: at, What: ChangeRole,
			From: string(a.Class.Role), To: string(c.Role)})
	}
	a.Class = c
}

// expire removes the assets nobody has seen for a while. The caller holds the
// lock.
func (inv *Inventory) expire(now time.Time) {
	if inv.ttl <= 0 {
		return
	}
	for id, a := range inv.byID {
		if now.Sub(a.LastSeen) <= inv.ttl {
			continue
		}
		inv.remove(id, a)
		inv.Expired++
	}
}

// evict drops the least recently seen asset, and says whether it managed to.
func (inv *Inventory) evict() bool {
	var oldest *Asset
	var oldestID string
	for id, a := range inv.byID {
		if oldest == nil || a.LastSeen.Before(oldest.LastSeen) {
			oldest, oldestID = a, id
		}
	}
	if oldest == nil {
		return false
	}
	inv.remove(oldestID, oldest)
	inv.Dropped++
	return true
}

// remove unlinks an asset from all three indexes. The caller holds the lock.
func (inv *Inventory) remove(id string, a *Asset) {
	delete(inv.byID, id)
	if a.Hardware != "" {
		delete(inv.byHW, a.Hardware)
	}
	for _, s := range a.Addrs {
		if ip, err := netip.ParseAddr(s); err == nil && inv.byAddr[ip] == a {
			delete(inv.byAddr, ip)
		}
	}
}

// Len is how many assets the inventory holds.
func (inv *Inventory) Len() int {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return len(inv.byID)
}

// List returns the assets, newest sighting first. The copies are deep enough
// that a caller cannot change the inventory by editing one.
func (inv *Inventory) List() []*Asset {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := make([]*Asset, 0, len(inv.byID))
	for _, a := range inv.byID {
		out = append(out, a.clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].ID < out[j].ID
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// Get returns one asset by identifier, address or hardware address, so that an
// operator looking at a log line can look the device up by whatever the line
// happened to carry.
func (inv *Inventory) Get(key string) (*Asset, bool) {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	if a := inv.byID[key]; a != nil {
		return a.clone(), true
	}
	if a := inv.byHW[normalHWString(key)]; a != nil {
		return a.clone(), true
	}
	if ip, err := netip.ParseAddr(key); err == nil {
		if a := inv.byAddr[ip]; a != nil {
			return a.clone(), true
		}
	}
	return nil, false
}

// Freeze takes the current set of identifiers as the baseline, so that
// everything seen afterwards that is not in it is reported as new.
//
// This is what turns the inventory from a reference document into a detection:
// an estate that knows what it has can be told when something else appears.
func (inv *Inventory) Freeze() int {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.baseline = make(map[string]bool, len(inv.byID))
	for id := range inv.byID {
		inv.baseline[id] = true
		inv.byID[id].New = false
	}
	return len(inv.baseline)
}

// Frozen says whether a baseline has been taken, and how large it is.
func (inv *Inventory) Frozen() (int, bool) {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return len(inv.baseline), inv.baseline != nil
}

// Thaw forgets the baseline.
//
// Every record's New flag goes with it. An estate that has no baseline has no
// opinion about what is new, and leaving the flag set would mean the summary
// said "no baseline" while the devices said "new" -- two answers to one
// question, which is how an operator stops believing either.
func (inv *Inventory) Thaw() {
	inv.mu.Lock()
	for _, a := range inv.byID {
		a.New = false
	}
	inv.baseline = nil
	inv.mu.Unlock()
}

// Counts are the inventory's own numbers, for the metrics.
type Counts struct {
	Assets   int
	New      int
	Unknown  int
	Dropped  uint64
	Expired  uint64
	Refused  uint64
	Findings uint64
	ByRole   map[Role]int
}

// Counts summarises the inventory.
func (inv *Inventory) Counts() Counts {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	c := Counts{Assets: len(inv.byID), Dropped: inv.Dropped,
		Expired: inv.Expired, Refused: inv.Refused, Findings: inv.Findings,
		ByRole: map[Role]int{}}
	for _, a := range inv.byID {
		c.ByRole[a.Class.Role]++
		if a.New {
			c.New++
		}
		if a.Class.Role == RoleUnknown {
			c.Unknown++
		}
	}
	return c
}

// clone copies an asset deeply enough to hand out.
func (a *Asset) clone() *Asset {
	c := *a
	c.Addrs = append([]string(nil), a.Addrs...)
	c.Listeners = append([]string(nil), a.Listeners...)
	c.Units = append([]int(nil), a.Units...)
	c.Objects = append([]int(nil), a.Objects...)
	c.Funcs = append([]int(nil), a.Funcs...)
	c.OIDs = append([]string(nil), a.OIDs...)
	c.Changes = append([]Change(nil), a.Changes...)
	c.Class.Why = append([]string(nil), a.Class.Why...)
	c.Protos = make(map[string]uint64, len(a.Protos))
	for k, v := range a.Protos {
		c.Protos[k] = v
	}
	return &c
}

// Speaks says whether an asset has been seen on a protocol.
func (a *Asset) Speaks(proto string) bool { _, ok := a.Protos[proto]; return ok }

// setIf keeps a peer-chosen string, clipped, and never erases one with an empty
// value: an observation that knows nothing about a field should not delete what
// another listener knew.
func setIf(dst *string, v string) {
	if v == "" {
		return
	}
	*dst = textsafe.Clip(v, MaxString)
}

func addSet(list []string, v string, max int) []string {
	if v == "" {
		return list
	}
	for _, s := range list {
		if s == v {
			return list
		}
	}
	if len(list) >= max {
		return list
	}
	return append(list, v)
}

func addInts(list []int, add []int) []int {
	for _, v := range add {
		found := false
		for _, s := range list {
			if s == v {
				found = true
				break
			}
		}
		if found {
			continue
		}
		if len(list) >= MaxProtos {
			return list
		}
		list = append(list, v)
	}
	sort.Ints(list)
	return list
}

func prependBounded(list []string, v string, max int) []string {
	out := make([]string, 0, max)
	out = append(out, v)
	for _, s := range list {
		if s == v {
			continue
		}
		if len(out) >= max {
			break
		}
		out = append(out, s)
	}
	return out
}

func appendBounded[T any](list []T, add []T, max int) []T {
	list = append(list, add...)
	if len(list) > max {
		// The newest changes are the interesting ones, so the oldest go.
		list = list[len(list)-max:]
	}
	return list
}
