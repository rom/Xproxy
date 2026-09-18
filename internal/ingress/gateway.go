package ingress

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// Gateway API (gateway.networking.k8s.io/v1) shapes, the fields used.

type objectRef struct {
	Group       string `json:"group"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	SectionName string `json:"sectionName"`
	Port        *int   `json:"port"`
	Weight      *int   `json:"weight"`
}

// Gateway is a Gateway resource.
type Gateway struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		GatewayClassName string `json:"gatewayClassName"`
		Listeners        []struct {
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			TLS      *struct {
				CertificateRefs []objectRef `json:"certificateRefs"`
			} `json:"tls"`
		} `json:"listeners"`
	} `json:"spec"`
}

type httpHeaderMatch struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type httpPathMatch struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type httpRouteMatch struct {
	Path    *httpPathMatch    `json:"path"`
	Headers []httpHeaderMatch `json:"headers"`
	Method  string            `json:"method"`
}

type headerModifier struct {
	Set    []struct{ Name, Value string } `json:"set"`
	Add    []struct{ Name, Value string } `json:"add"`
	Remove []string                       `json:"remove"`
}

type httpRouteFilter struct {
	Type                   string          `json:"type"`
	RequestHeaderModifier  *headerModifier `json:"requestHeaderModifier"`
	ResponseHeaderModifier *headerModifier `json:"responseHeaderModifier"`
	URLRewrite             *struct {
		Hostname string `json:"hostname"`
		Path     *struct {
			Type               string `json:"type"`
			ReplacePrefixMatch string `json:"replacePrefixMatch"`
			ReplaceFullPath    string `json:"replaceFullPath"`
		} `json:"path"`
	} `json:"urlRewrite"`
	RequestRedirect *struct {
		Scheme     string `json:"scheme"`
		Hostname   string `json:"hostname"`
		Port       *int   `json:"port"`
		StatusCode int    `json:"statusCode"`
		Path       *struct {
			Type            string `json:"type"`
			ReplaceFullPath string `json:"replaceFullPath"`
		} `json:"path"`
	} `json:"requestRedirect"`
}

type httpRouteRule struct {
	Matches     []httpRouteMatch  `json:"matches"`
	Filters     []httpRouteFilter `json:"filters"`
	BackendRefs []objectRef       `json:"backendRefs"`
}

// HTTPRoute is an HTTPRoute resource.
type HTTPRoute struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		ParentRefs []objectRef     `json:"parentRefs"`
		Hostnames  []string        `json:"hostnames"`
		Rules      []httpRouteRule `json:"rules"`
	} `json:"spec"`
}

// gatewayKey identifies a Gateway.
func gatewayKey(ns, name string) string { return ns + "/" + name }

// translateGateway adds the routes, upstreams and certificates of the
// Gateways of class and the HTTPRoutes attached to them. endpointsFor
// resolves a service port to ready endpoints (shared with the Ingress
// translation).
func translateGateway(in Input, class string, snap *Snapshot, endpointsFor func(ns, svc string, port int, portName string) ([]config.Endpoint, error)) {
	warn := func(kind, ns, name, format string, args ...any) {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("%s %s/%s: ", kind, ns, name)+fmt.Sprintf(format, args...))
	}
	gateways := map[string]*Gateway{}
	for i := range in.Gateways {
		g := &in.Gateways[i]
		if g.Spec.GatewayClassName != class {
			continue
		}
		if !labelRE.MatchString(g.Metadata.Namespace) || !labelRE.MatchString(g.Metadata.Name) {
			warn("gateway", g.Metadata.Namespace, g.Metadata.Name, "name or namespace is not a DNS label")
			continue
		}
		gateways[gatewayKey(g.Metadata.Namespace, g.Metadata.Name)] = g
		snap.Gateways++
		for _, l := range g.Spec.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, ref := range l.TLS.CertificateRefs {
				ns := ref.Namespace
				if ns == "" {
					ns = g.Metadata.Namespace
				}
				if ref.Kind != "" && ref.Kind != "Secret" {
					warn("gateway", g.Metadata.Namespace, g.Metadata.Name, "listener %s: certificate ref kind %s not supported", l.Name, ref.Kind)
					continue
				}
				s, ok := in.Secrets[ns+"/"+ref.Name]
				if !ok || s == nil {
					warn("gateway", g.Metadata.Namespace, g.Metadata.Name, "listener %s: tls secret %s not found", l.Name, ref.Name)
					continue
				}
				addCert(snap, ns, ref.Name, s, []string{l.Hostname}, func(f string, a ...any) { warn("gateway", g.Metadata.Namespace, g.Metadata.Name, f, a...) })
			}
		}
	}
	for i := range in.HTTPRoutes {
		hr := &in.HTTPRoutes[i]
		ns, name := hr.Metadata.Namespace, hr.Metadata.Name
		if !labelRE.MatchString(ns) || !labelRE.MatchString(name) {
			continue
		}
		var parents []*Gateway
		for _, p := range hr.Spec.ParentRefs {
			if p.Kind != "" && p.Kind != "Gateway" {
				continue
			}
			pns := p.Namespace
			if pns == "" {
				pns = ns
			}
			if g, ok := gateways[gatewayKey(pns, p.Name)]; ok {
				parents = append(parents, g)
			}
		}
		if len(parents) == 0 {
			continue // attached to another controller's gateway, or none
		}
		snap.HTTPRoutes++
		// Hostnames: the route's own, else the listeners' of the parents.
		var hosts []string
		for _, h := range hr.Spec.Hostnames {
			hosts = append(hosts, strings.ToLower(h))
		}
		if len(hosts) == 0 {
			for _, g := range parents {
				for _, l := range g.Spec.Listeners {
					if l.Hostname != "" {
						hosts = append(hosts, strings.ToLower(l.Hostname))
					}
				}
			}
		}
		hosts = dedupe(hosts)
		for ri, rule := range hr.Spec.Rules {
			base := config.Route{Hosts: hosts}
			redirect := false
			for _, f := range rule.Filters {
				switch f.Type {
				case "RequestHeaderModifier":
					base.RequestHeaders = headerOps(f.RequestHeaderModifier)
				case "ResponseHeaderModifier":
					base.ResponseHeaders = headerOps(f.ResponseHeaderModifier)
				case "URLRewrite":
					if f.URLRewrite == nil {
						continue
					}
					if f.URLRewrite.Hostname != "" {
						base.HostHeader = f.URLRewrite.Hostname
					}
					if p := f.URLRewrite.Path; p != nil {
						switch {
						case p.Type == "ReplaceFullPath" && strings.HasPrefix(p.ReplaceFullPath, "/"):
							base.RewritePath = p.ReplaceFullPath
						case p.Type == "ReplacePrefixMatch" && (p.ReplacePrefixMatch == "/" || p.ReplacePrefixMatch == ""):
							base.StripPrefix = "match" // resolved per match below
						default:
							warn("httproute", ns, name, "rule %d: URLRewrite path %s %q not supported (only ReplaceFullPath and ReplacePrefixMatch to /)", ri, p.Type, p.ReplacePrefixMatch+p.ReplaceFullPath)
						}
					}
				case "RequestRedirect":
					rr := f.RequestRedirect
					if rr == nil {
						continue
					}
					if rr.Hostname == "" {
						warn("httproute", ns, name, "rule %d: RequestRedirect without hostname not supported (the proxy cannot redirect to the same host with another scheme per route; use redirect_to_https on the listener)", ri)
						continue
					}
					scheme := rr.Scheme
					if scheme == "" {
						scheme = "https"
					}
					host := rr.Hostname
					if rr.Port != nil {
						host = net.JoinHostPort(host, strconv.Itoa(*rr.Port))
					}
					to := scheme + "://" + host
					if rr.Path != nil && rr.Path.Type == "ReplaceFullPath" && strings.HasPrefix(rr.Path.ReplaceFullPath, "/") {
						to += rr.Path.ReplaceFullPath
					}
					status := rr.StatusCode
					if status == 0 {
						status = 302
					}
					base.Redirect = &config.Redirect{To: to, Status: status}
					redirect = true
				default:
					warn("httproute", ns, name, "rule %d: filter %s not supported", ri, f.Type)
				}
			}
			if !redirect {
				up, err := gatewayUpstream(ns, name, ri, rule.BackendRefs, endpointsFor)
				if err != nil {
					warn("httproute", ns, name, "rule %d: %v", ri, err)
					continue
				}
				if up != nil {
					snap.Upstreams = append(snap.Upstreams, *up)
					base.Upstream = up.Name
				}
			}
			matches := rule.Matches
			if len(matches) == 0 {
				matches = []httpRouteMatch{{Path: &httpPathMatch{Type: "PathPrefix", Value: "/"}}}
			}
			for mi, m := range matches {
				r := base
				path, ptype := "/", "PathPrefix"
				if m.Path != nil {
					if m.Path.Value != "" {
						path = m.Path.Value
					}
					if m.Path.Type != "" {
						ptype = m.Path.Type
					}
				}
				if ptype == "RegularExpression" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "*?#") {
					warn("httproute", ns, name, "rule %d match %d: path %s %q not supported", ri, mi, ptype, path)
					continue
				}
				if len(m.Headers) > 0 {
					warn("httproute", ns, name, "rule %d match %d: header matches are not supported; the match is applied without them", ri, mi)
				}
				r.Name = objName("gw", ns, name, strconv.Itoa(ri), strconv.Itoa(mi))
				r.Paths = []string{path}
				if ptype == "Exact" {
					r.Priority = 10
				}
				if m.Method != "" {
					r.Methods = []string{strings.ToUpper(m.Method)}
				}
				if r.StripPrefix == "match" {
					if path == "/" {
						r.StripPrefix = ""
					} else {
						r.StripPrefix = strings.TrimSuffix(path, "/")
					}
				}
				if r.Upstream == "" && r.Redirect == nil {
					continue
				}
				snap.Routes = append(snap.Routes, r)
			}
		}
	}
}

// gatewayUpstream builds one upstream for a rule's backend references:
// one service directly, several as a weighted pool over all their
// endpoints.
func gatewayUpstream(ns, route string, rule int, refs []objectRef, endpointsFor func(ns, svc string, port int, portName string) ([]config.Endpoint, error)) (*config.Upstream, error) {
	live := make([]objectRef, 0, len(refs))
	for _, ref := range refs {
		if ref.Kind != "" && ref.Kind != "Service" {
			continue
		}
		if ref.Weight != nil && *ref.Weight == 0 {
			continue
		}
		live = append(live, ref)
	}
	if len(live) == 0 {
		return nil, fmt.Errorf("no service backend")
	}
	up := &config.Upstream{Name: objName("gw", ns, route, strconv.Itoa(rule)), Scheme: "http"}
	if len(live) > 1 {
		up.Balancer = "weighted"
	}
	for _, ref := range live {
		rns := ref.Namespace
		if rns == "" {
			rns = ns
		}
		port := 0
		if ref.Port != nil {
			port = *ref.Port
		}
		eps, err := endpointsFor(rns, ref.Name, port, "")
		if err != nil {
			return nil, err
		}
		w := 1
		if ref.Weight != nil {
			w = min(*ref.Weight, 1000)
		}
		for _, e := range eps {
			e.Weight = w
			up.Endpoints = append(up.Endpoints, e)
		}
	}
	sort.Slice(up.Endpoints, func(i, j int) bool { return up.Endpoints[i].Address < up.Endpoints[j].Address })
	return up, nil
}

func headerOps(m *headerModifier) config.HeaderOps {
	var ops config.HeaderOps
	if m == nil {
		return ops
	}
	for _, h := range m.Set {
		if ops.Set == nil {
			ops.Set = map[string]string{}
		}
		ops.Set[h.Name] = h.Value
	}
	for _, h := range m.Add {
		if ops.Add == nil {
			ops.Add = map[string]string{}
		}
		ops.Add[h.Name] = h.Value
	}
	ops.Remove = append(ops.Remove, m.Remove...)
	return ops
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// addCert appends a secret's material once.
func addCert(snap *Snapshot, ns, name string, s *Secret, hosts []string, warn func(string, ...any)) {
	for _, c := range snap.Certificates {
		if c.Namespace == ns && c.Name == name {
			return
		}
	}
	crt, key := s.Data["tls.crt"], s.Data["tls.key"]
	if crt == "" || key == "" {
		warn("tls secret %s lacks tls.crt or tls.key", name)
		return
	}
	cb, err1 := decodeB64(crt)
	kb, err2 := decodeB64(key)
	if err1 != nil || err2 != nil || len(cb) == 0 || len(kb) == 0 {
		warn("tls secret %s is not valid base64", name)
		return
	}
	snap.Certificates = append(snap.Certificates, CertPEM{Namespace: ns, Name: name, Cert: cb, Key: kb, Hosts: hosts})
}
