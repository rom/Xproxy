package tlsconf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/secret"
)

// Tickets manages TLS session ticket keys for every listener. Keys are
// not random per process: they are derived from a master secret file and
// the current time epoch (now / rotate), so every node that holds the
// same file computes the same keys at the same time and a session ticket
// issued by one node resumes on another without any message between
// them. The current epoch's key encrypts new tickets; the previous
// epoch's key is kept so that tickets issued just before a rotation
// still resume. Rotating the master with xproxyctl rotate-secret keeps
// the older masters for one more epoch through the keyring's previous
// keys.
type Tickets struct {
	ring   *secret.Keyring
	rotate time.Duration
	now    func() time.Time
	log    *slog.Logger
	// OnRotate is called with the new fingerprint after every key change
	// (the cluster publishes it so peers can detect disagreement).
	OnRotate func(fingerprint string)

	mu       sync.Mutex
	configs  []*tls.Config
	epoch    int64
	keys     [][32]byte
	fp       string
	peers    map[string]string // peer -> fingerprint reported
	stop     chan struct{}
	done     chan struct{}
	rotated  uint64
	mismatch uint64
}

// TicketStatus is the management view (GET /v1/tls/tickets).
type TicketStatus struct {
	Enabled      bool      `json:"enabled"`
	Rotate       string    `json:"rotate"`
	Epoch        int64     `json:"epoch"`
	EpochStarted time.Time `json:"epoch_started"`
	NextRotation time.Time `json:"next_rotation"`
	// Keys is the number of ticket keys installed (current and previous
	// epoch for every master key); Fingerprint identifies the set.
	Keys        int    `json:"keys"`
	Fingerprint string `json:"fingerprint"`
	MasterKeys  int    `json:"master_keys"`
	Rotations   uint64 `json:"rotations"`
	// Peers maps cluster peers to the fingerprint they reported;
	// MismatchedPeers lists those whose set differs from ours.
	Peers           map[string]string `json:"peers,omitempty"`
	MismatchedPeers []string          `json:"mismatched_peers,omitempty"`
}

// NewTickets loads (or creates) the master secret and derives the keys.
func NewTickets(cfg *config.SessionTickets, log *slog.Logger) (*Tickets, error) {
	ring, err := secret.LoadOrCreate(cfg.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("session_tickets.secret_file: %w", err)
	}
	t := &Tickets{ring: ring, rotate: cfg.Rotate.D(), now: time.Now, log: log, peers: map[string]string{}}
	t.mu.Lock()
	t.derive(t.currentEpoch())
	t.mu.Unlock()
	return t, nil
}

func (t *Tickets) currentEpoch() int64 { return t.now().UnixNano() / int64(t.rotate) }

// derive computes the key set for epoch e. Caller holds mu.
func (t *Tickets) derive(e int64) {
	masters := t.ring.All()
	keys := make([][32]byte, 0, 2*len(masters))
	for _, ep := range []int64{e, e - 1} {
		for _, m := range masters {
			var info [16]byte
			copy(info[:8], "xpticket")
			binary.BigEndian.PutUint64(info[8:], uint64(ep)) //nolint:gosec // epoch is positive
			k, err := hkdf.Key(sha256.New, m, nil, string(info[:]), 32)
			if err != nil {
				continue
			}
			var kk [32]byte
			copy(kk[:], k)
			keys = append(keys, kk)
		}
	}
	t.epoch, t.keys = e, keys
	h := sha256.New()
	for _, k := range keys {
		h.Write(k[:])
	}
	t.fp = hex.EncodeToString(h.Sum(nil))[:16]
	for _, c := range t.configs {
		c.SetSessionTicketKeys(keys)
	}
}

// Attach installs the keys on a listener's configuration and keeps it
// for later rotations.
func (t *Tickets) Attach(tc *tls.Config) {
	if t == nil || tc == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.configs = append(t.configs, tc)
	tc.SetSessionTicketKeys(t.keys)
}

// Start begins epoch tracking; keys switch within a minute of the
// boundary.
func (t *Tickets) Start() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.stop != nil {
		t.mu.Unlock()
		return
	}
	t.stop, t.done = make(chan struct{}), make(chan struct{})
	stop, done := t.stop, t.done
	t.mu.Unlock()
	go func() {
		defer close(done)
		tk := time.NewTicker(time.Minute)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				t.Tick()
			}
		}
	}()
}

// Tick re-derives the keys when the epoch changed (the loop calls it every
// minute; tests call it directly).
func (t *Tickets) Tick() {
	if t == nil {
		return
	}
	t.mu.Lock()
	e := t.currentEpoch()
	if e == t.epoch {
		t.mu.Unlock()
		return
	}
	t.derive(e)
	t.rotated++
	fp := t.fp
	cb := t.OnRotate
	t.mu.Unlock()
	t.log.Info("session ticket keys rotated", "epoch", e, "fingerprint", fp)
	if cb != nil {
		cb(fp)
	}
}

// Stop ends epoch tracking.
func (t *Tickets) Stop() {
	if t == nil {
		return
	}
	t.mu.Lock()
	stop, done := t.stop, t.done
	t.stop, t.done = nil, nil
	t.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}

// Fingerprint identifies the current key set.
func (t *Tickets) Fingerprint() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fp
}

// PeerFingerprint records what a cluster peer reported and returns
// whether it matches ours.
func (t *Tickets) PeerFingerprint(peer, fp string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[peer] = fp
	if fp != t.fp {
		t.mismatch++
		return false
	}
	return true
}

// Status returns the management view.
func (t *Tickets) Status() *TicketStatus {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := &TicketStatus{Enabled: true, Rotate: t.rotate.String(), Epoch: t.epoch,
		EpochStarted: time.Unix(0, t.epoch*int64(t.rotate)), NextRotation: time.Unix(0, (t.epoch+1)*int64(t.rotate)),
		Keys: len(t.keys), Fingerprint: t.fp, MasterKeys: t.ring.Len(), Rotations: t.rotated}
	if len(t.peers) > 0 {
		st.Peers = make(map[string]string, len(t.peers))
		for p, fp := range t.peers {
			st.Peers[p] = fp
			if fp != t.fp {
				st.MismatchedPeers = append(st.MismatchedPeers, p)
			}
		}
		sort.Strings(st.MismatchedPeers)
	}
	return st
}
