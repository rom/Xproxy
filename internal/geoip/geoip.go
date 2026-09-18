package geoip

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Source answers country lookups.
type Source interface {
	Country(netip.Addr) string
}

// DB is the configured database with a bounded lookup cache and counters.
type DB struct {
	src    Source
	kind   string
	path   string
	loaded time.Time
	built  time.Time

	mu    sync.Mutex
	cache map[netip.Addr]string
	order []netip.Addr

	lookups atomic.Uint64
	unknown atomic.Uint64
}

const cacheSize = 65536

// Open loads the database named by the configuration.
func Open(cfg *config.GeoIP) (*DB, error) {
	db := &DB{cache: make(map[netip.Addr]string, 1024), loaded: time.Now()}
	switch {
	case cfg.Database != "":
		m, err := OpenMMDB(cfg.Database)
		if err != nil {
			return nil, err
		}
		db.src, db.kind, db.path = m, "mmdb:"+m.Type(), cfg.Database
		if e := m.BuildEpoch(); e > 0 && e < 1<<40 {
			db.built = time.Unix(int64(e), 0) //nolint:gosec // bounded above
		}
	case cfg.CSV != "":
		t, err := OpenCSV(cfg.CSV)
		if err != nil {
			return nil, err
		}
		db.src, db.kind, db.path = t, "csv", cfg.CSV
	default:
		return nil, errors.New("geoip: database or csv is required")
	}
	return db, nil
}

// Country returns the ISO code for an address, or "" when unknown.
// Results are cached per address (bounded, FIFO eviction).
func (db *DB) Country(addr netip.Addr) string {
	addr = addr.Unmap()
	db.lookups.Add(1)
	db.mu.Lock()
	if c, ok := db.cache[addr]; ok {
		db.mu.Unlock()
		if c == "" {
			db.unknown.Add(1)
		}
		return c
	}
	db.mu.Unlock()
	c := db.src.Country(addr)
	if c == "" {
		db.unknown.Add(1)
	}
	db.mu.Lock()
	if len(db.cache) >= cacheSize {
		for i := 0; i < cacheSize/8 && len(db.order) > 0; i++ {
			delete(db.cache, db.order[0])
			db.order = db.order[1:]
		}
	}
	db.cache[addr] = c
	db.order = append(db.order, addr)
	db.mu.Unlock()
	return c
}

// Status is the management view.
type Status struct {
	Kind     string    `json:"kind"`
	Path     string    `json:"path"`
	Loaded   time.Time `json:"loaded"`
	Built    time.Time `json:"built,omitempty"`
	Lookups  uint64    `json:"lookups"`
	Unknown  uint64    `json:"unknown"`
	Cached   int       `json:"cached"`
	Prefixes int       `json:"prefixes,omitempty"`
}

// Status reports the database and counters.
func (db *DB) Status() Status {
	db.mu.Lock()
	cached := len(db.cache)
	db.mu.Unlock()
	st := Status{Kind: db.kind, Path: db.path, Loaded: db.loaded, Built: db.built, Lookups: db.lookups.Load(), Unknown: db.unknown.Load(), Cached: cached}
	if t, ok := db.src.(*Table); ok {
		st.Prefixes = t.Len()
	}
	return st
}
