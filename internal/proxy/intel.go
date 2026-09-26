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

// feedToken resolves a feed's credential. A plain value is taken as written, so
// nothing already configured changes; a reference goes through the resolver, so
// the token can live in a vault and be rotated there.
func feedToken(ref string, res *keysource.Resolver) (string, error) {
	if ref == "" {
		return "", nil
	}
	if res == nil {
		// Only reachable where a Set is built with no resolver. Saying so beats
		// sending a literal "env:TOKEN" to a TAXII server, which answers 401
		// and leaves a list that never updates.
		if _, err := keysource.Parse(ref); err == nil && !isPlainToken(ref) {
			return "", fmt.Errorf("%q is a reference and no secret resolver is configured", ref)
		}
		return ref, nil
	}
	if isPlainToken(ref) {
		return ref, nil
	}
	return res.StringValue(ref)
}

// isPlainToken reports whether a value is a literal credential rather than a
// reference. A token is opaque, so the test is whether it names a scheme this
// resolves -- and a path is not one, because a bare path in this field is far
// more likely to be a token that happens to start with a slash than a file
// somebody meant to read.
func isPlainToken(v string) bool {
	r, err := keysource.Parse(v)
	if err != nil {
		return true
	}
	return r.Scheme == keysource.SchemeFile && !hasScheme(v)
}

// hasScheme reports whether a reference was written with one.
func hasScheme(v string) bool {
	for _, p := range []string{keysource.SchemeFile + ":", keysource.SchemeEnv + ":", keysource.SchemeVault + ":"} {
		if len(v) >= len(p) && v[:len(p)] == p {
			return true
		}
	}
	return false
}
