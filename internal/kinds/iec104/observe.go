package iec104

import (
	"sync"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/netutil"
)

// What this listener tells the estate's device inventory.
//
// IEC 104 is the clearest of the industrial protocols for this purpose, because
// the standard names the two ends: a *controlling station* asks and a
// *controlled station* answers. A relay sits between them and sees which is
// which, and the common addresses that go past are the substations the
// controlling station is responsible for -- which is the first thing a
// segmentation review wants and the last thing anybody has written down.
//
// The reporting is once per association, not once per frame: an IEC 104 link
// carries interrogations continuously and stays up for months.

// watcher accumulates the common addresses one association named.
type watcher struct {
	mu      sync.Mutex
	commons map[int]bool
	first   bool
}

// maxWatched bounds the common addresses one association remembers. A
// controlling station that named more than this many is a scan, and the first
// sixty-four say so as well as all of them.
const maxWatched = 64

func newWatcher() *watcher { return &watcher{commons: map[int]bool{}} }

func (w *watcher) saw(a *wire.ASDU) (firstFrame bool) {
	if a == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.commons) < maxWatched {
		w.commons[int(a.Common)] = true
	}
	if w.first {
		return false
	}
	w.first = true
	return true
}

func (w *watcher) lists() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int, 0, len(w.commons))
	for c := range w.commons {
		out = append(out, c)
	}
	return out
}

func (w *watcher) anything() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.first
}

// observeFrame reports the first frame of an association, so that a link up for
// a month appears in the inventory in its first second.
func (t *server) observeFrame(se *session, a *wire.ASDU) {
	if !se.watch.saw(a) {
		return
	}
	t.observeStation(se)
}

// observeStation reports the controlling station: the end that connected and
// asks. On this protocol that is the supervisory side by definition.
func (t *server) observeStation(se *session) {
	t.host.ObserveAsset(assets.Observation{
		Listener: t.cfg.Name, Proto: "iec104", Addr: se.ip,
		Server: false, Objects: se.watch.lists(),
	})
}

// observeSubstation reports the controlled station this association reached:
// the end that answers, which is the remote terminal unit.
func (t *server) observeSubstation(addr string, commons []int) {
	ip := netutil.AddrOf(addr)
	if !ip.IsValid() {
		return
	}
	t.host.ObserveAsset(assets.Observation{
		Listener: t.cfg.Name, Proto: "iec104", Addr: ip,
		Server: true, Objects: commons,
	})
}
