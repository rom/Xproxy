package proxy

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
)

// The device inventory the engine owns.
//
// It lives here rather than in a listener kind because it is one record per
// device across every kind: a controller seen by the Modbus relay and given its
// address by the DHCP relay is one device, and two listeners in two daemons
// cannot merge that between them. The engine has the process, so the engine has
// the inventory.
//
// Nothing here probes anything. Every entry is a by-product of traffic the proxy
// was already carrying, which is the whole reason an inventory can exist on a
// network where a scan is not allowed.

// assetKeeper owns the inventory, its file and its alert policy.
type assetKeeper struct {
	inv *assets.Inventory
	cfg *config.AssetInventory
	srv *Server

	// expected is the allow list of roles, empty when the estate did not say.
	expected map[assets.Role]bool

	// adv is the advisory matcher, or nil when the configuration has none.
	adv *advisories

	path     string
	every    time.Duration
	once     sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
	saveFail uint64
}

// newAssetKeeper builds the inventory from the configuration.
func newAssetKeeper(s *Server, c *config.AssetInventory) (*assetKeeper, error) {
	k := &assetKeeper{cfg: c, srv: s, path: c.StateFile, done: make(chan struct{}),
		every: c.SaveInterval.D()}
	if k.every <= 0 {
		k.every = 5 * time.Minute
	}
	if len(c.Roles) > 0 {
		k.expected = make(map[assets.Role]bool, len(c.Roles))
		for _, name := range c.Roles {
			// Validation has already refused a name that is not a role.
			if r, ok := assets.RoleOf(name); ok {
				k.expected[r] = true
			}
		}
		// A role nothing can be classified as would make every unclassified
		// device a finding, which is noise rather than detection.
		k.expected[assets.RoleUnknown] = true
	}
	vendors := assets.SeedVendors()
	if c.VendorFile != "" {
		fh, err := os.Open(c.VendorFile) //nolint:gosec // an operator named this path
		if err != nil {
			return nil, err
		}
		n, err := vendors.Load(fh, 0)
		_ = fh.Close()
		if err != nil {
			return nil, err
		}
		s.logs.Error.Info("asset inventory vendor list loaded",
			"file", c.VendorFile, "entries", n, "total", vendors.Len())
	}
	k.inv = assets.New(assets.Options{Max: c.MaxAssets, TTL: c.TTL.D(),
		Vendors: vendors, OnChange: k.changed})
	if c.Advisories != nil && c.Advisories.Enabled {
		adv, err := newAdvisories(s, c.Advisories)
		if err != nil {
			// A source that cannot be read is a startup error, unlike the
			// state file below: an inventory that starts empty loses history,
			// and an advisory set that starts empty reports an estate as
			// having nothing against it.
			return nil, err
		}
		k.adv = adv
	}
	if k.path != "" {
		n, err := k.inv.Load(k.path)
		if err != nil {
			// A state file that will not read is reported and not fatal: an
			// inventory is a record, and refusing to start the proxy over one
			// would make the record more important than the traffic.
			s.logs.Error.Warn("asset inventory could not be read",
				"file", k.path, "error", err.Error())
		} else if n > 0 {
			s.logs.Error.Info("asset inventory read", "file", k.path, "assets", n)
		}
	}
	return k, nil
}

// changed is called for every identity change the inventory notices.
//
// This is where an inventory stops being a reference document. The deltas are
// the security value: an address taken over by another device, a device whose
// role changed, something that was not in the frozen baseline.
func (k *assetKeeper) changed(a *assets.Asset, c assets.Change) {
	k.srv.stats.AssetFindings.Add(1)
	switch c.What {
	case assets.ChangeNew:
		if k.cfg.AlertOnNew != nil && !*k.cfg.AlertOnNew {
			return
		}
	default:
		if k.cfg.AlertOnChange != nil && !*k.cfg.AlertOnChange {
			return
		}
	}
	attrs := []any{"proto", "assets", "change", c.What, "asset", a.ID,
		"role", string(a.Class.Role), "confidence", a.Class.Confidence}
	if a.Hardware != "" {
		attrs = append(attrs, "hardware_address", a.Hardware, "vendor", a.Vendor)
	}
	if len(a.Addrs) > 0 {
		attrs = append(attrs, "address", a.Addrs[0])
	}
	if c.From != "" {
		attrs = append(attrs, "from", c.From)
	}
	if c.To != "" {
		attrs = append(attrs, "to", c.To)
	}
	if len(a.Listeners) > 0 {
		attrs = append(attrs, "listener", a.Listeners[0])
	}
	// alert, not deny: the inventory refuses nothing. An operator filtering
	// the security log for what the proxy blocked must not find entries that
	// blocked nothing.
	k.srv.logs.SecurityEvent(context.Background(), "alert", "asset_"+c.What, attrs...)
}

// observe records an observation and checks the role against the estate's own
// list, which is how "there are no engineering workstations on the process
// network" is written down.
func (k *assetKeeper) observe(o assets.Observation) {
	a := k.inv.Observe(o)
	if a == nil {
		return
	}
	k.srv.stats.AssetObservations.Add(1)
	if k.adv != nil {
		// Assessed when the device says something about itself, and reported
		// only when the answer is new: the matcher remembers what it has
		// already said about this device at this version.
		k.adv.assess(a)
	}
	if k.expected == nil || k.expected[a.Class.Role] {
		return
	}
	// A role this estate did not say it has. It is reported once per
	// observation rather than once per asset on purpose: a device that keeps
	// behaving like something it should not be is a thing that keeps happening,
	// and a single event at first sighting is one an operator scrolls past.
	k.srv.stats.AssetUnexpected.Add(1)
	if k.cfg.AlertOnChange != nil && !*k.cfg.AlertOnChange {
		return
	}
	k.srv.logs.SecurityEvent(context.Background(), "alert", "asset_unexpected_role",
		"proto", "assets", "asset", a.ID, "role", string(a.Class.Role),
		"confidence", a.Class.Confidence, "why", firstWhy(a))
}

func firstWhy(a *assets.Asset) string {
	if len(a.Class.Why) == 0 {
		return ""
	}
	return a.Class.Why[0]
}

// start begins writing the file and re-reading the advisories.
func (k *assetKeeper) start() {
	if k.adv != nil {
		k.advisoryLoop(k.cfg.Advisories.RefreshInterval().D())
		// The estate as it stands, against the advisories as they are now.
		// Without this the first assessment of a device read back from the
		// state file would wait for it to say something again, which on a
		// controller that reports its firmware once at connection could be
		// months.
		for _, one := range k.inv.List() {
			k.adv.assess(one)
		}
	}
	if k.path == "" {
		return
	}
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		t := time.NewTicker(k.every)
		defer t.Stop()
		for {
			select {
			case <-k.done:
				return
			case <-t.C:
				k.save()
			}
		}
	}()
}

// stop writes the file one last time and stops the writer.
//
// The last write matters: an inventory whose final minutes were lost would
// report the devices seen in them as new on the next start, and a new-device
// alert that fires because the proxy restarted is one an operator learns to
// ignore.
func (k *assetKeeper) stop() {
	k.once.Do(func() { close(k.done) })
	k.wg.Wait()
	k.save()
}

func (k *assetKeeper) save() {
	if k.path == "" {
		return
	}
	if err := k.inv.Save(k.path); err != nil {
		k.saveFail++
		k.srv.stats.AssetSaveFailures.Add(1)
		k.srv.logs.Error.Warn("asset inventory could not be written",
			"file", k.path, "error", err.Error())
	}
}

// Assets is the device inventory, or nil when the configuration has none.
//
// A kind checks for nil rather than the engine handing out an inventory nobody
// asked for: an inventory is a record of somebody's estate, and a proxy that
// kept one without being told to would be making a decision about their data for
// them.
func (s *Server) Assets() *assets.Inventory {
	if k := s.assets.Load(); k != nil {
		return k.inv
	}
	return nil
}

// ObserveAsset records what a listener noticed about a device. It is a no-op
// without an inventory, so a kind writes no conditionals around it.
func (s *Server) ObserveAsset(o assets.Observation) {
	if k := s.assets.Load(); k != nil {
		k.observe(o)
	}
}

// AssetReport is the inventory's summary for a status view, or nil when the
// configuration has no inventory.
func (s *Server) AssetReport() *AssetSummary {
	k := s.assets.Load()
	if k == nil {
		return nil
	}
	c := k.inv.Counts()
	size, frozen := k.inv.Frozen()
	sum := &AssetSummary{Assets: c.Assets, New: c.New, Unknown: c.Unknown,
		Dropped: c.Dropped, Expired: c.Expired, Refused: c.Refused,
		Findings: c.Findings, Frozen: frozen, Baseline: size,
		ByRole: make(map[string]int, len(c.ByRole))}
	for r, n := range c.ByRole {
		sum.ByRole[string(r)] = n
	}
	return sum
}

// AssetCounts is the inventory's own summary, for the status view.
func (s *Server) AssetCounts() (assets.Counts, bool) {
	k := s.assets.Load()
	if k == nil {
		return assets.Counts{}, false
	}
	return k.inv.Counts(), true
}
