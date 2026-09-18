package ingress

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/rom/xproxy/internal/config"
)

// Merge appends a snapshot's routes and upstreams to the operator's
// configuration and adds the certificate files to the ingress listener,
// then runs the result through the ordinary parser so every default and
// validation rule applies. base is not modified.
func Merge(base *config.Config, snap Snapshot, certs []config.Certificate) (*config.Config, error) {
	if base.Ingress == nil || !base.Ingress.Enabled {
		return nil, ErrNotEnabled
	}
	raw, err := yaml.Marshal(base)
	if err != nil {
		return nil, err
	}
	var c config.Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	// base already carries its fragments' sections; parsing the merged
	// document must not append them a second time.
	c.Includes = nil
	names := map[string]bool{}
	for _, u := range c.Upstreams {
		names[u.Name] = true
	}
	for _, u := range snap.Upstreams {
		if names[u.Name] {
			return nil, fmt.Errorf("ingress upstream %s collides with the configuration", u.Name)
		}
		c.Upstreams = append(c.Upstreams, u)
	}
	routes := map[string]bool{}
	for _, r := range c.Routes {
		routes[r.Name] = true
	}
	for _, r := range snap.Routes {
		if routes[r.Name] {
			return nil, fmt.Errorf("ingress route %s collides with the configuration", r.Name)
		}
		c.Routes = append(c.Routes, r)
	}
	if ln := base.Ingress.Listener; ln != "" && len(certs) > 0 {
		found := false
		for i := range c.Server.Listeners {
			if c.Server.Listeners[i].Name == ln {
				found = true
				if c.Server.Listeners[i].TLS == nil {
					return nil, fmt.Errorf("ingress listener %s has no tls section", ln)
				}
				c.Server.Listeners[i].TLS.Certificates = append(c.Server.Listeners[i].TLS.Certificates, certs...)
			}
		}
		if !found {
			return nil, fmt.Errorf("ingress listener %s not found", ln)
		}
	}
	out, err := yaml.Marshal(&c)
	if err != nil {
		return nil, err
	}
	merged, err := config.Parse(out)
	if err != nil {
		return nil, fmt.Errorf("ingress merge: %w", err)
	}
	return merged, nil
}
