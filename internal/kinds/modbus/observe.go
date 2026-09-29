package modbus

import (
	"net/netip"
	"sync"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/netutil"
)

// What this listener tells the estate's device inventory.
//
// Modbus is the most informative protocol here for that purpose, because the
// direction of a request says what each end is: the controller answers and the
// thing driving the process asks. A relay sees both ends of that, which is
// something neither end can see about itself.
//
// The cost has to be watched. A Modbus session is a device's connection that
// lives for as long as the plant runs and carries a frame every few
// milliseconds, so an observation per frame would be a lock per frame on a path
// whose whole design is not to add latency to a scan. So the session accumulates
// what it saw and reports twice: once on the first frame, so a device appears in
// the inventory while it is still connected, and once at the end with everything
// it did.

// watcher accumulates what one session saw, bounded.
type watcher struct {
	mu     sync.Mutex
	units  map[int]bool
	funcs  map[int]bool
	first  bool
	writes bool
}

// maxWatched bounds the unit identifiers and function codes one session
// remembers. A session that used more than this many of either is a scanner, and
// the first sixty-four of each say so just as well as all of them.
const maxWatched = 64

func newWatcher() *watcher {
	return &watcher{units: map[int]bool{}, funcs: map[int]bool{}}
}

// saw records one frame and says whether this is the first.
func (w *watcher) saw(unit uint8, pdu *wire.PDU) (firstFrame bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.units) < maxWatched {
		w.units[int(unit)] = true
	}
	if len(w.funcs) < maxWatched {
		w.funcs[int(pdu.Function)] = true
	}
	if pdu.Access == wire.AccessWrite {
		w.writes = true
	}
	if w.first {
		return false
	}
	w.first = true
	return true
}

// anything says whether the session saw a frame at all, so a connection that
// was refused before it spoke does not become an inventory entry.
func (w *watcher) anything() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.first
}

// lists are what the session saw, as the inventory wants them.
func (w *watcher) lists() (units, funcs []int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	units = make([]int, 0, len(w.units))
	for u := range w.units {
		units = append(units, u)
	}
	funcs = make([]int, 0, len(w.funcs))
	for f := range w.funcs {
		funcs = append(funcs, f)
	}
	return units, funcs
}

// observeFrame reports the first frame of a session, so that a device connected
// for a month appears in the inventory in the first second rather than when it
// disconnects.
func (t *server) observeFrame(se *session, frame *wire.Frame, pdu *wire.PDU) {
	if !se.watch.saw(frame.Unit, pdu) {
		return
	}
	t.observeClient(se)
}

// observeClient reports what the connecting end is. It asked rather than
// answered, which is what separates a panel or a historian from a controller.
func (t *server) observeClient(se *session) {
	units, funcs := se.watch.lists()
	t.host.ObserveAsset(assets.Observation{
		Listener: t.cfg.Name, Proto: "modbus", Addr: se.ip,
		Server: false, Units: units, Funcs: funcs,
	})
}

// observeDevice reports the device a worker reached. This end *answered*, which
// is the strongest evidence in the whole fingerprint set: a thing that answers
// Modbus on a unit identifier is a thing that answers Modbus on a unit
// identifier, and no vendor class can say otherwise.
func (t *server) observeDevice(addr string, unit uint8) {
	ip := netutil.AddrOf(addr)
	if !ip.IsValid() {
		return
	}
	t.host.ObserveAsset(assets.Observation{
		Listener: t.cfg.Name, Proto: "modbus", Addr: ip,
		Server: true, Units: []int{int(unit)},
	})
}

// observeIdentity reports what a device said about itself.
//
// Function code 43 with MEI type 14 is the only place in this protocol where a
// device names its vendor, its product and its firmware revision, and the only
// way those reach an inventory without somebody scanning the network. So the
// answer to a master's own identification request is read on its way past.
//
// Nothing here asks the question. A relay that issued a request of its own
// would be putting a frame on a process network that nobody scheduled, on a
// protocol where a device answering one has a bounded number of things it can
// do at once -- and a firmware version is not worth a frame the plant did not
// plan for. If no master ever asks, the inventory simply does not know, and the
// advisory matching says "not assessed" rather than guessing.
func (t *server) observeIdentity(addr string, unit uint8, id *wire.DeviceIdentity) {
	ip := netutil.AddrOf(addr)
	if !ip.IsValid() {
		return
	}
	o, ok := identityObservation(t.cfg.Name, ip, unit, id)
	if !ok {
		return
	}
	t.host.ObserveAsset(o)
}

// identityObservation turns an identification response into an observation, or
// says there was nothing in it an inventory can use.
//
// It is separate from the call above so that what a device's answer *becomes*
// can be checked without a network: the mapping is the part with a decision in
// it, and the call is a line of plumbing.
func identityObservation(listener string, ip netip.Addr, unit uint8, id *wire.DeviceIdentity) (assets.Observation, bool) {
	if id.Empty() {
		return assets.Observation{}, false
	}
	// ModelName is what a device is called and ProductName what family it
	// belongs to; an advisory names either, so the more specific one is
	// preferred and the other kept where it is the only one given.
	model := id.Model
	if model == "" {
		model = id.Product
	}
	switch {
	case model == "":
		model = id.ProductCode
	case id.ProductCode != "" && model != id.ProductCode:
		// The product code is the orderable part number and is what a vendor's
		// advisory often names -- "BMXP342020" rather than "Modicon M340" --
		// so both go in, in the order a reader would write them.
		model += " " + id.ProductCode
	}
	return assets.Observation{
		Listener: listener, Proto: "modbus", Addr: ip,
		Server: true, Units: []int{int(unit)},
		Maker: id.Vendor, Model: model, Firmware: id.Revision,
		Description: id.Application,
	}, true
}
