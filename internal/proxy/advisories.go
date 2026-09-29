package proxy

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/csaf"
)

// The inventory, matched against the vendors' own security advisories.
//
// The inventory beside this knows what is on the network and, for the protocols
// where a device says so, what firmware each one reports. A CSAF 2.0 directory
// says which products and which version ranges each CVE affects. Putting the
// two together answers the question an estate that cannot patch actually has --
// not "is there an advisory for this controller" but "is the version we are
// running one of the affected ones" -- and answers it from traffic that was
// already crossing the relay, on a network where a vulnerability scanner is not
// allowed through the door.
//
// Three rules about *when* it decides, which are what keep this from becoming a
// second log of everything:
//
//   - A device is assessed when what it says about itself changes, not when it
//     sends a frame. A controller polled every ten milliseconds would otherwise
//     be assessed every ten milliseconds against the same advisories, to the
//     same answer.
//   - An event is written once per device per version, and the memo that
//     remembers that is bounded by the inventory's own bound. A device that is
//     affected stays affected until somebody updates it; saying so once is a
//     finding and saying so per frame is a reason to turn logging off.
//   - A refresh that brings in new documents re-assesses the estate, because
//     that is the moment an advisory published this morning meets a controller
//     installed in 2013. It is the one time the matching runs over every device
//     at once, and it runs on the refresh goroutine rather than on a listener's.
type advisories struct {
	cfg *config.Advisories
	set *csaf.Set
	srv *Server

	// sources are the configured sources, translated once.
	sources []csaf.Source

	// mu guards the memo of what has already been reported.
	mu sync.Mutex
	// reported keys an asset to the (maker, model, firmware, state) it was
	// last reported at, so that an unchanged answer is not an event again.
	reported map[string]string
	// affected is the devices currently in the affected state, which is the
	// gauge an operator watches: a number that goes up when a new advisory
	// lands and down as an estate is patched.
	affected map[string]bool
	// notAssessed is the devices whose exposure could not be established. It
	// is a *list* rather than a count on purpose: "these eleven have to be
	// checked by hand" is the sentence this feature owes an operator.
	notAssessed map[string]string
}

// maxMemo bounds the reported and not-assessed maps. It is the inventory's own
// bound: a memo larger than the inventory it remembers would be remembering
// devices the inventory has already forgotten.
const maxMemo = assets.DefaultMax

// newAdvisories builds the matcher, reading every source. A source that cannot
// be read is a load error, for the reason the csaf package gives: an empty set
// that looks like a populated one is the failure mode worth refusing at start,
// when somebody is watching.
func newAdvisories(s *Server, c *config.Advisories) (*advisories, error) {
	a := &advisories{cfg: c, srv: s, reported: map[string]string{},
		affected: map[string]bool{}, notAssessed: map[string]string{}}
	for _, src := range c.Sources {
		a.sources = append(a.sources, csaf.Source{Name: src.Name, File: src.File,
			Directory: src.Directory})
	}
	set, err := csaf.Load(a.sources, csaf.Options{})
	if err != nil {
		return nil, err
	}
	a.set = set
	c2 := set.Counts()
	s.logs.Error.Info("security advisories loaded", "documents", c2.Documents,
		"records", c2.Records, "sources", len(c2.Sources))
	return a, nil
}

// refresh re-reads the sources and re-assesses the estate.
func (a *advisories) refresh(inv *assets.Inventory) {
	before := a.set.Documents()
	if err := a.set.Refresh(a.sources); err != nil {
		// The rule is the same as the imported-list package's: what is loaded
		// is kept, and the failure is reported rather than silently emptying
		// the assessment. A set that has quietly stopped updating is the
		// failure worth alerting on, so it is counted as well as logged.
		a.srv.stats.AdvisoryFailures.Add(1)
		a.srv.logs.Error.Warn("security advisories could not be re-read",
			"error", err.Error())
	}
	if a.set.Documents() == before {
		return
	}
	// New documents. This is the moment an advisory published this morning
	// meets a controller installed in 2013, so the whole estate is assessed
	// again rather than waiting for each device to say something.
	a.srv.logs.Error.Info("security advisories changed",
		"documents", a.set.Documents(), "was", before)
	for _, one := range inv.List() {
		a.assess(one)
	}
}

// subjectOf is what the matcher is asked about.
//
// The maker the device named itself is preferred over the vendor a hardware
// prefix resolved to, because a prefix belongs to whoever made the network
// module and the device's own answer names whoever made the device. Neither is
// required: the product name is what the match is made on.
func subjectOf(one *assets.Asset) csaf.Subject {
	sub := csaf.Subject{ID: one.ID, Vendor: one.Maker, Model: one.Model,
		Firmware: one.Firmware}
	if sub.Vendor == "" {
		sub.Vendor = one.Vendor
	}
	return sub
}

// assess matches one device and writes an event when the answer is new.
func (a *advisories) assess(one *assets.Asset) {
	if one == nil || one.Model == "" {
		// Nothing to match on. A device that has never said what it is cannot
		// be tied to a product, and inventing a match from an address would be
		// the guess this whole feature refuses to make. The status view still
		// reports such a device, saying that; an event about it would be an
		// event about the inventory rather than about an advisory.
		return
	}
	got := a.set.Assess(subjectOf(one))
	key := strings.Join([]string{one.Maker, one.Model, one.Firmware, got.State, got.Worst}, "\x00")
	a.mu.Lock()
	seen := a.reported[one.ID] == key
	if !seen && len(a.reported) < maxMemo {
		a.reported[one.ID] = key
	}
	switch got.State {
	case csaf.StateAffected:
		a.affected[one.ID] = true
		delete(a.notAssessed, one.ID)
	case csaf.StateNotAssessed:
		delete(a.affected, one.ID)
		if len(a.notAssessed) < maxMemo {
			a.notAssessed[one.ID] = got.Reason
		}
	default:
		delete(a.affected, one.ID)
		delete(a.notAssessed, one.ID)
	}
	nAffected, nUnassessed := len(a.affected), len(a.notAssessed)
	a.mu.Unlock()
	a.srv.stats.AdvisoryAffected.Store(uint64(nAffected))      //nolint:gosec // a map length
	a.srv.stats.AdvisoryNotAssessed.Store(uint64(nUnassessed)) //nolint:gosec // a map length
	if seen {
		return
	}
	a.report(one, got)
}

// report writes the security event for one device's assessment.
func (a *advisories) report(one *assets.Asset, got *csaf.Assessment) {
	switch got.State {
	case csaf.StateAffected:
		a.srv.stats.AdvisoryFindings.Add(1)
		if !a.cfg.AlertsOnAffected() {
			return
		}
		if !csaf.SeverityAtLeast(got.Worst, a.cfg.MinSeverity) {
			return
		}
	case csaf.StateNotAssessed:
		if !a.cfg.AlertsOnNotAssessed() {
			return
		}
	default:
		// fixed, not_affected, under_investigation and unknown_product are the
		// states an operator reads in the status view rather than in the
		// security log. A log line per device that is *not* affected is how a
		// useful signal becomes an unread one.
		return
	}
	attrs := []any{"proto", "assets", "asset", one.ID, "state", got.State,
		"model", one.Model, "firmware", firmwareOf(one)}
	if got.Vendor != "" {
		attrs = append(attrs, "vendor", got.Vendor)
	}
	if len(one.Addrs) > 0 {
		attrs = append(attrs, "address", one.Addrs[0])
	}
	if got.Reason != "" {
		attrs = append(attrs, "reason", got.Reason)
	}
	if got.Worst != "" {
		attrs = append(attrs, "severity", got.Worst, "score", got.Score)
	}
	if n := len(got.Hits); n > 0 {
		h := got.Hits[0]
		attrs = append(attrs, "advisory", h.Advisory, "advisories", got.Total)
		if h.CVE != "" {
			attrs = append(attrs, "cve", h.CVE)
		}
		if h.Fixed != "" {
			attrs = append(attrs, "fixed_in", h.Fixed)
		}
		if h.Publisher != "" {
			attrs = append(attrs, "publisher", h.Publisher)
		}
	}
	// alert, not deny: this refuses nothing. An operator filtering the security
	// log for what the proxy blocked must not find entries that blocked
	// nothing -- and an advisory is somebody else's statement about a product,
	// not this relay's decision about a frame.
	a.srv.logs.SecurityEvent(context.Background(), "alert", "asset_advisory_"+got.State, attrs...)
}

// firmwareOf is the version an event reports, which is "none reported" rather
// than an empty field when the device never said: the difference between a
// device on an old firmware and a device that does not say is the difference
// between a finding and a gap.
func firmwareOf(one *assets.Asset) string {
	if one.Firmware == "" {
		return "none reported"
	}
	return one.Firmware
}

// Assessments is every device the advisories have something to say about, worst
// first, for the status view and the control plane.
func (a *advisories) assessments(inv *assets.Inventory) []*csaf.Assessment {
	all := inv.List()
	out := make([]*csaf.Assessment, 0, len(all))
	for _, one := range all {
		if got := a.set.Assess(subjectOf(one)); got != nil {
			out = append(out, got)
		}
	}
	return out
}

// Counts is the advisory set's own summary.
func (a *advisories) counts() csaf.Counts { return a.set.Counts() }

// AdvisoryReport is what the control plane answers: the sources, the documents
// and the devices.
type AdvisoryReport struct {
	Counts csaf.Counts `json:"counts"`
	// Assessments are the devices, worst state first. A caller may ask for one
	// state, which is how "give me the ones nobody has assessed" is asked.
	Assessments []*csaf.Assessment `json:"assessments"`
	// Advisories are the documents themselves, newest first, when asked for.
	Advisories []*csaf.Advisory `json:"advisories,omitempty"`
}

// Advisories is the advisory matcher, or nil when the configuration has none.
func (s *Server) Advisories() *csaf.Set {
	if k := s.assets.Load(); k != nil && k.adv != nil {
		return k.adv.set
	}
	return nil
}

// AdvisoryReport answers the control plane's advisory view.
func (s *Server) AdvisoryReport(state string, withDocs bool) *AdvisoryReport {
	k := s.assets.Load()
	if k == nil || k.adv == nil {
		return nil
	}
	rep := &AdvisoryReport{Counts: k.adv.counts()}
	for _, one := range k.adv.assessments(k.inv) {
		if state != "" && one.State != state {
			continue
		}
		rep.Assessments = append(rep.Assessments, one)
	}
	if withDocs {
		rep.Advisories = k.adv.set.Advisories()
	}
	return rep
}

// refreshEvery is the advisory refresh loop, started with the keeper.
func (k *assetKeeper) advisoryLoop(every time.Duration) {
	if k.adv == nil || every <= 0 {
		return
	}
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-k.done:
				return
			case <-t.C:
				k.adv.refresh(k.inv)
			}
		}
	}()
}
