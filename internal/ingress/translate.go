package ingress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// AnnotationPrefix is the prefix of the Ingress annotations Xproxy reads.
const AnnotationPrefix = "xproxy.sysctl.se/"

// Snapshot is what a set of Ingress resources translates to.
type Snapshot struct {
	Routes       []config.Route
	Upstreams    []config.Upstream
	Certificates []CertPEM
	// Warnings are per object problems that did not stop the rest.
	Warnings []string
	// Ingresses, Gateways and HTTPRoutes counted after class filtering.
	Ingresses  int
	Gateways   int
	HTTPRoutes int
}

// CertPEM is a TLS secret's material, written to files by the controller.
type CertPEM struct {
	Namespace string
	Name      string
	Cert      []byte
	Key       []byte
	Hosts     []string
}

// Input is everything Translate needs, fetched by the controller.
type Input struct {
	Ingresses  []Ingress
	Gateways   []Gateway
	HTTPRoutes []HTTPRoute
	Services   []Service
	Slices     []EndpointSlice
	Secrets    map[string]*Secret // "namespace/name"
}

// endpointResolver maps a service port to ready endpoints.
type endpointResolver struct {
	services map[string]*Service
	slices   map[string][]*EndpointSlice
}

func newEndpointResolver(in Input) *endpointResolver {
	r := &endpointResolver{services: map[string]*Service{}, slices: map[string][]*EndpointSlice{}}
	for i := range in.Services {
		s := &in.Services[i]
		r.services[s.Metadata.Namespace+"/"+s.Metadata.Name] = s
	}
	for i := range in.Slices {
		s := &in.Slices[i]
		key := s.Metadata.Namespace + "/" + s.Metadata.Labels["kubernetes.io/service-name"]
		r.slices[key] = append(r.slices[key], s)
	}
	return r
}

// resolve returns the ready endpoints of service ns/svc on the port
// given by number or name (a service with one port needs neither) and
// the service port number; a service without ready endpoints yields an
// unreachable placeholder so the route answers 503 rather than vanish.
func (r *endpointResolver) resolve(ns, svc string, port int, portName string) ([]config.Endpoint, int, error) {
	s, ok := r.services[ns+"/"+svc]
	if !ok {
		return nil, 0, fmt.Errorf("service %s not found", svc)
	}
	epName, epPort, found := "", 0, false
	for _, p := range s.Spec.Ports {
		if (port != 0 && p.Port == port) || (portName != "" && p.Name == portName) {
			epName, epPort, found = p.Name, p.Port, true
			break
		}
	}
	if !found && len(s.Spec.Ports) == 1 && port == 0 && portName == "" {
		epName, epPort, found = s.Spec.Ports[0].Name, s.Spec.Ports[0].Port, true
	}
	if !found {
		return nil, 0, fmt.Errorf("service %s has no port %d%s", svc, port, portName)
	}
	var eps []config.Endpoint
	seen := map[string]bool{}
	for _, sl := range r.slices[ns+"/"+svc] {
		if sl.AddressType != "IPv4" && sl.AddressType != "IPv6" {
			continue
		}
		target := 0
		for _, p := range sl.Ports {
			if p.Name == epName && (p.Protocol == "" || p.Protocol == "TCP") {
				target = p.Port
			}
		}
		if target == 0 {
			continue
		}
		for _, e := range sl.Endpoints {
			if e.Conditions.Ready != nil && !*e.Conditions.Ready {
				continue
			}
			for _, a := range e.Addresses {
				addr := net.JoinHostPort(a, strconv.Itoa(target))
				if !seen[addr] {
					seen[addr] = true
					eps = append(eps, config.Endpoint{Address: addr})
				}
			}
		}
	}
	if len(eps) == 0 {
		eps = []config.Endpoint{{Address: "127.0.0.1:1"}}
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].Address < eps[j].Address })
	return eps, epPort, nil
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// hostRE is a DNS name, optionally with the leading wildcard label an
// Ingress rule may carry. A rule's host becomes a route host in the
// proxy's own configuration, and it is written by whoever can create an
// Ingress in a namespace, so it is checked rather than trusted.
var hostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$`)

// hostOK reports whether a rule's host can be a route host.
func hostOK(h string) bool { return len(h) <= 253 && hostRE.MatchString(h) }

// pathOK reports whether a rule's path can be a route path: a plain
// prefix with nothing in it that a header, a log line or a routing key
// would have to escape.
func pathOK(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 2048 {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return false
		}
	}
	return true
}

// objName builds a configuration name from Kubernetes names; a name
// over the 64 byte bound is shortened with a digest so it stays unique.
func objName(parts ...string) string {
	n := "k8s-" + strings.Join(parts, "-")
	if len(n) > 64 {
		sum := sha256.Sum256([]byte(n))
		n = n[:55] + "-" + hex.EncodeToString(sum[:4])
	}
	return n
}

// Translate builds routes and upstreams for the Ingresses of class.
// Objects with problems are skipped with a warning; the rest still
// translates.
func Translate(in Input, class string) Snapshot {
	var snap Snapshot
	warn := func(ing *Ingress, format string, args ...any) {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("%s/%s: ", ing.Metadata.Namespace, ing.Metadata.Name)+fmt.Sprintf(format, args...))
	}
	resolver := newEndpointResolver(in)
	upstreams := map[string]*config.Upstream{}
	var upstreamOrder []string
	upstreamFor := func(ing *Ingress, b *backend) (string, bool) {
		if b == nil || b.Service == nil || b.Service.Name == "" {
			warn(ing, "backend without a service")
			return "", false
		}
		ns := ing.Metadata.Namespace
		eps, portNumber, err := resolver.resolve(ns, b.Service.Name, b.Service.Port.Number, b.Service.Port.Name)
		if err != nil {
			warn(ing, "%v", err)
			return "", false
		}
		name := objName(ns, b.Service.Name, strconv.Itoa(portNumber))
		if _, ok := upstreams[name]; ok {
			return name, true
		}
		if len(eps) == 1 && eps[0].Address == "127.0.0.1:1" {
			warn(ing, "service %s has no ready endpoints; using an unreachable placeholder", b.Service.Name)
		}
		upstreams[name] = &config.Upstream{Name: name, Endpoints: eps, Scheme: "http"}
		upstreamOrder = append(upstreamOrder, name)
		return name, true
	}

	seenDefault := false
	for i := range in.Ingresses {
		ing := &in.Ingresses[i]
		if !matchesClass(ing, class) {
			continue
		}
		if !labelRE.MatchString(ing.Metadata.Namespace) || !labelRE.MatchString(ing.Metadata.Name) {
			warn(ing, "name or namespace is not a DNS label")
			continue
		}
		snap.Ingresses++
		ann := ing.Metadata.Annotations
		n := 0
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				up, ok := upstreamFor(ing, &p.Backend)
				if !ok {
					continue
				}
				path := p.Path
				if path == "" {
					path = "/"
				}
				if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "*?#") {
					warn(ing, "path %q is not a plain prefix (regular expressions are not supported)", path)
					continue
				}
				if !pathOK(path) {
					warn(ing, "path %q carries a space or a control character", path)
					continue
				}
				if rule.Host != "" && !hostOK(strings.ToLower(rule.Host)) {
					warn(ing, "host %q is not a DNS name", rule.Host)
					continue
				}
				r := config.Route{Name: objName(ing.Metadata.Namespace, ing.Metadata.Name, strconv.Itoa(n)), Paths: []string{path}, Upstream: up}
				n++
				if rule.Host != "" {
					r.Hosts = []string{strings.ToLower(rule.Host)}
				}
				if p.PathType == "Exact" {
					r.Priority = 10 // exact paths rank above prefixes of equal length
				}
				applyAnnotations(&r, ann, path, warn, ing)
				snap.Routes = append(snap.Routes, r)
			}
		}
		if ing.Spec.DefaultBackend != nil {
			if seenDefault {
				warn(ing, "a default backend is already defined by another Ingress; ignored")
			} else if up, ok := upstreamFor(ing, ing.Spec.DefaultBackend); ok {
				seenDefault = true
				r := config.Route{Name: objName(ing.Metadata.Namespace, ing.Metadata.Name, "default"), Paths: []string{"/"}, Upstream: up, Priority: -100}
				applyAnnotations(&r, ann, "/", warn, ing)
				snap.Routes = append(snap.Routes, r)
			}
		}
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue
			}
			s, ok := in.Secrets[ing.Metadata.Namespace+"/"+t.SecretName]
			if !ok || s == nil {
				warn(ing, "tls secret %s not found", t.SecretName)
				continue
			}
			if s.Type != "" && s.Type != "kubernetes.io/tls" {
				// The Ingress API requires a kubernetes.io/tls secret;
				// anything else is a secret that was not meant to be a
				// certificate, and pointing at one should not publish it.
				warn(ing, "tls secret %s is of type %s, not kubernetes.io/tls", t.SecretName, s.Type)
				continue
			}
			crt, key := s.Data["tls.crt"], s.Data["tls.key"]
			if crt == "" || key == "" {
				warn(ing, "tls secret %s lacks tls.crt or tls.key", t.SecretName)
				continue
			}
			cb, err1 := decodeB64(crt)
			kb, err2 := decodeB64(key)
			if err1 != nil || err2 != nil || len(cb) == 0 || len(kb) == 0 {
				warn(ing, "tls secret %s is not valid base64", t.SecretName)
				continue
			}
			dup := false
			for _, c := range snap.Certificates {
				if c.Namespace == ing.Metadata.Namespace && c.Name == t.SecretName {
					dup = true
				}
			}
			if !dup {
				snap.Certificates = append(snap.Certificates, CertPEM{Namespace: ing.Metadata.Namespace, Name: t.SecretName, Cert: cb, Key: kb, Hosts: t.Hosts})
			}
		}
	}
	for _, name := range upstreamOrder {
		snap.Upstreams = append(snap.Upstreams, *upstreams[name])
	}
	translateGateway(in, class, &snap, func(ns, svc string, port int, portName string) ([]config.Endpoint, error) {
		eps, _, err := resolver.resolve(ns, svc, port, portName)
		return eps, err
	})
	return snap
}

func matchesClass(ing *Ingress, class string) bool {
	if ing.Spec.IngressClassName != "" {
		return ing.Spec.IngressClassName == class
	}
	if a := ing.Metadata.Annotations["kubernetes.io/ingress.class"]; a != "" {
		return a == class
	}
	return false
}

// applyAnnotations reads the xproxy.sysctl.se/* annotations.
func applyAnnotations(r *config.Route, ann map[string]string, path string, warn func(*Ingress, string, ...any), ing *Ingress) {
	get := func(k string) string { return strings.TrimSpace(ann[AnnotationPrefix+k]) }
	if v := get("websocket"); v == "true" {
		r.WebSocket = true
	}
	if v := get("priority-class"); v != "" {
		r.PriorityClass = v
	}
	if v := get("rate-limits"); v != "" {
		r.RateLimits = splitList(v)
	}
	if v := get("filters"); v != "" {
		r.Filters = splitList(v)
	}
	if v := get("timeout"); v != "" {
		var d config.Duration
		if err := d.UnmarshalYAML(func(x any) error { *(x.(*string)) = v; return nil }); err != nil {
			warn(ing, "timeout annotation %q: %v", v, err)
		} else {
			r.Timeout = d
		}
	}
	if v := get("max-body-bytes"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			r.MaxBodyBytes = &n
		} else {
			warn(ing, "max-body-bytes annotation %q is not a positive integer", v)
		}
	}
	if v := get("strip-prefix"); v == "true" && path != "/" {
		r.StripPrefix = strings.TrimSuffix(path, "/")
	}
	if v := get("host-header"); v != "" {
		r.HostHeader = v
	}
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
