package modbus

import (
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
