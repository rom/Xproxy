package proxy

import (
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/intel"
)

// newIntel builds the imported lists from the configuration. A file that
// cannot be read fails here, which is why it is called before the plane
// is switched: an imported list that silently matches nothing is worse
// than none, because the operator believes it works.
func newIntel(cfg *config.ThreatIntel) (*intel.Set, error) {
	specs := make([]intel.Spec, 0, len(cfg.Lists))
	for _, l := range cfg.Lists {
		specs = append(specs, intel.Spec{Name: l.Name, Kind: l.Kind, Action: l.Action, File: l.File})
	}
	return intel.New(specs)
}
