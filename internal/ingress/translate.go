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
	// Ingresses counted after class filtering.
	Ingresses int
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
	Ingresses []Ingress
	Services  []Service
	Slices    []EndpointSlice
	Secrets   map[string]*Secret // "namespace/name"
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

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
	services := map[string]*Service{}
	for i := range in.Services {
		s := &in.Services[i]
		services[s.Metadata.Namespace+"/"+s.Metadata.Name] = s
	}
	slices := map[string][]*EndpointSlice{}
	for i := range in.Slices {
		s := &in.Slices[i]
		key := s.Metadata.Namespace + "/" + s.Metadata.Labels["kubernetes.io/service-name"]
		slices[key] = append(slices[key], s)
	}
	upstreams := map[string]*config.Upstream{}
	var upstreamOrder []string
	upstreamFor := func(ing *Ingress, b *backend) (string, bool) {
		if b == nil || b.Service == nil || b.Service.Name == "" {
			warn(ing, "backend without a service")
			return "", false
		}
		ns := ing.Metadata.Namespace
		svc, ok := services[ns+"/"+b.Service.Name]
		if !ok {
			warn(ing, "service %s not found", b.Service.Name)
			return "", false
		}
		// Resolve the service port to its name, then the name to the
		// endpoint port in the slices.
		portName, portNumber := "", 0
		found := false
		for _, p := range svc.Spec.Ports {
			if (b.Service.Port.Number != 0 && p.Port == b.Service.Port.Number) || (b.Service.Port.Name != "" && p.Name == b.Service.Port.Name) {
				portName, portNumber, found = p.Name, p.Port, true
				break
			}
		}
		if !found && len(svc.Spec.Ports) == 1 && b.Service.Port.Number == 0 && b.Service.Port.Name == "" {
			portName, portNumber, found = svc.Spec.Ports[0].Name, svc.Spec.Ports[0].Port, true
		}
		if !found {
			warn(ing, "service %s has no port %d%s", b.Service.Name, b.Service.Port.Number, b.Service.Port.Name)
			return "", false
		}
		name := objName(ns, b.Service.Name, strconv.Itoa(portNumber))
		if _, ok := upstreams[name]; ok {
			return name, true
		}
		var eps []config.Endpoint
		seen := map[string]bool{}
		for _, sl := range slices[ns+"/"+b.Service.Name] {
			if sl.AddressType != "IPv4" && sl.AddressType != "IPv6" {
				continue
			}
			target := 0
			for _, p := range sl.Ports {
				if p.Name == portName && (p.Protocol == "" || p.Protocol == "TCP") {
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
			warn(ing, "service %s has no ready endpoints; using an unreachable placeholder", b.Service.Name)
			eps = []config.Endpoint{{Address: "127.0.0.1:1"}}
		}
		sort.Slice(eps, func(i, j int) bool { return eps[i].Address < eps[j].Address })
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
