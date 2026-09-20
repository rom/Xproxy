package ingress

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// decode builds the typed list a watch would produce from a literal.
func decode[T any](t *testing.T, items ...any) []T {
	t.Helper()
	b, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	var l list[T]
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	return l.Items
}

func tlsSecret() *Secret {
	return &Secret{Type: "kubernetes.io/tls", Data: map[string]string{
		"tls.crt": base64.StdEncoding.EncodeToString([]byte("CERT")),
		"tls.key": base64.StdEncoding.EncodeToString([]byte("KEY")),
	}}
}

func gatewayObj(ns, name string, from any, certRef map[string]any) map[string]any {
	listener := map[string]any{"name": "https", "hostname": "*.example.com", "port": 443, "protocol": "HTTPS",
		"tls": map[string]any{"certificateRefs": []any{certRef}}}
	if from != nil {
		listener["allowedRoutes"] = map[string]any{"namespaces": map[string]any{"from": from}}
	}
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"gatewayClassName": "xproxy", "listeners": []any{listener}}}
}

func routeObj(ns, name, parentNS, parent, host string) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns}, "spec": map[string]any{
		"parentRefs": []any{map[string]any{"name": parent, "namespace": parentNS}},
		"hostnames":  []any{host},
		"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "svc", "port": 80}}}},
	}}
}

// TestGatewayRouteAttachmentNeedsAllowedRoutes: a Gateway belongs to the
// namespace that created it. Without allowedRoutes the Gateway API
// default is "Same", so a route from another tenant's namespace must not
// attach — it could otherwise claim any hostname on a shared gateway.
func TestGatewayRouteAttachmentNeedsAllowedRoutes(t *testing.T) {
	ref := map[string]any{"name": "wild-tls"}
	in := Input{Secrets: map[string]*Secret{"infra/wild-tls": tlsSecret()}}
	in.Gateways = decode[Gateway](t, gatewayObj("infra", "edge", nil, ref))
	in.HTTPRoutes = decode[HTTPRoute](t,
		routeObj("evil", "hijack", "infra", "edge", "bank.example.com"),
		routeObj("infra", "own", "infra", "edge", "ok.example.com"),
	)
	in.Services = decode[Service](t, serviceObj("evil", "svc", 80, "http", 8080), serviceObj("infra", "svc", 80, "http", 8080))
	snap := Translate(in, "xproxy")
	for _, r := range snap.Routes {
		for _, h := range r.Hosts {
			if h == "bank.example.com" {
				t.Fatalf("a route from another namespace attached to the gateway: %+v", r)
			}
		}
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "namespace") {
		t.Fatalf("refusal not reported: %v", snap.Warnings)
	}
	// The gateway's own namespace still attaches.
	found := false
	for _, r := range snap.Routes {
		for _, h := range r.Hosts {
			if h == "ok.example.com" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("same-namespace route refused: %+v", snap.Routes)
	}
}

// TestGatewayAllowedRoutesAll: the gateway owner opts in with
// allowedRoutes.namespaces.from All, and then other namespaces attach.
func TestGatewayAllowedRoutesAll(t *testing.T) {
	in := Input{Secrets: map[string]*Secret{"infra/wild-tls": tlsSecret()}}
	in.Gateways = decode[Gateway](t, gatewayObj("infra", "edge", "All", map[string]any{"name": "wild-tls"}))
	in.HTTPRoutes = decode[HTTPRoute](t, routeObj("shop", "shop", "infra", "edge", "shop.example.com"))
	in.Services = decode[Service](t, serviceObj("shop", "svc", 80, "http", 8080))
	snap := Translate(in, "xproxy")
	found := false
	for _, r := range snap.Routes {
		for _, h := range r.Hosts {
			if h == "shop.example.com" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("route refused although the gateway allows every namespace: %+v %v", snap.Routes, snap.Warnings)
	}
}

// TestGatewaySelectorNotSupported: a namespace selector cannot be
// evaluated without namespace labels, so it denies rather than admits.
func TestGatewaySelectorNotSupported(t *testing.T) {
	in := Input{Secrets: map[string]*Secret{"infra/wild-tls": tlsSecret()}}
	in.Gateways = decode[Gateway](t, gatewayObj("infra", "edge", "Selector", map[string]any{"name": "wild-tls"}))
	in.HTTPRoutes = decode[HTTPRoute](t, routeObj("shop", "shop", "infra", "edge", "shop.example.com"))
	in.Services = decode[Service](t, serviceObj("shop", "svc", 80, "http", 8080))
	snap := Translate(in, "xproxy")
	for _, r := range snap.Routes {
		for _, h := range r.Hosts {
			if h == "shop.example.com" {
				t.Fatalf("selector treated as All: %+v", r)
			}
		}
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "selector") {
		t.Fatalf("selector refusal not reported: %v", snap.Warnings)
	}
}

// TestGatewayCertificateRefStaysInNamespace: a certificateRef naming
// another namespace needs a ReferenceGrant there, which is not
// implemented; without that check any tenant able to create a Gateway
// could mount any TLS private key in the cluster and have it served for
// a hostname of their choosing.
func TestGatewayCertificateRefStaysInNamespace(t *testing.T) {
	in := Input{Secrets: map[string]*Secret{
		"infra/wild-tls": tlsSecret(),
		"evil/own-tls":   tlsSecret(),
	}}
	in.Gateways = decode[Gateway](t,
		gatewayObj("evil", "steal", "All", map[string]any{"namespace": "infra", "name": "wild-tls"}),
	)
	snap := Translate(in, "xproxy")
	if len(snap.Certificates) != 0 {
		t.Fatalf("another namespace's certificate installed: %+v", snap.Certificates)
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "namespace") {
		t.Fatalf("refusal not reported: %v", snap.Warnings)
	}
	// The same reference inside the gateway's own namespace works, and an
	// explicit namespace equal to the gateway's is not a cross reference.
	in.Gateways = decode[Gateway](t,
		gatewayObj("evil", "own", "All", map[string]any{"namespace": "evil", "name": "own-tls"}),
	)
	snap = Translate(in, "xproxy")
	if len(snap.Certificates) != 1 || snap.Certificates[0].Namespace != "evil" {
		t.Fatalf("same-namespace certificate refused: %+v %v", snap.Certificates, snap.Warnings)
	}
}
