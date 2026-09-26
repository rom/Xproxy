package proxy

import (
	"fmt"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/intel"
	"github.com/rom/xproxy/internal/keysource"
)

// newIntel builds the imported lists from the configuration. A file that
// cannot be read, and a feed that cannot be fetched, fail here -- which is why
// it is called before the plane is switched: an imported list that silently
// matches nothing is worse than none, because the operator believes it works.
//
// res resolves a feed's credential from a reference, so a TAXII token or a MISP
// API key can live in a vault rather than in the configuration. It may be nil in
// the paths that have no resolver yet, and then a reference is an error rather
// than a token nobody notices is missing.
func newIntel(cfg *config.ThreatIntel, res *keysource.Resolver) (*intel.Set, error) {
	specs := make([]intel.Spec, 0, len(cfg.Lists))
	for _, l := range cfg.Lists {
		sp := intel.Spec{
			Name: l.Name, Kind: l.Kind, Action: l.Action,
			File: l.File, URL: l.URL, Format: l.Format,
		}
		if t := l.TAXII; t != nil {
			sp.TAXII = &intel.TAXIISpec{APIRoot: t.APIRoot, Collection: t.Collection, AddedAfter: t.AddedAfter}
		}
		if m := l.MISP; m != nil {
			sp.MISP = &intel.MISPSpec{
				BaseURL: m.URL, Types: m.Types, Tags: m.Tags,
				Published: m.Published == nil || *m.Published, Limit: m.Limit,
			}
		}
		if h := l.HTTP; h != nil {
			token, err := feedToken(h.Token, res)
			if err != nil {
				return nil, fmt.Errorf("threat_intel list %q: http.token: %w", l.Name, err)
			}
			sp.HTTP = &intel.HTTPSpec{
				Timeout: h.Timeout.D(), Token: token,
				Header: h.Header, HeaderValue: h.HeaderValue,
				CAFile: h.CAFile, ServerName: h.ServerName,
				Insecure: h.Insecure, AllowInsecure: h.AllowInsecure,
			}
		}
		specs = append(specs, sp)
	}
	set, err := intel.New(specs)
	if err != nil {
		return nil, err
	}
	// The log_matches decision travels with the set, so every listener kind
	// that matches a list asks the same object the same question.
	set.SetLogs(cfg.Logs())
	return set, nil
}

// feedToken resolves a feed's credential: a literal value as written, or a
// reference through the resolver so the token can live in a vault and be
// rotated there. The rule is keysource's, because an approval service's
// credential is written the same way and two answers to "is this a reference"
// would be two behaviours.
func feedToken(ref string, res *keysource.Resolver) (string, error) {
	return keysource.Token(ref, res)
}
