// Package ingress turns Kubernetes Ingress resources into Xproxy routes,
// upstreams and certificates. It talks to the API server directly with
// the pod's service account (no client-go), polls the resources it needs
// on a fixed interval and hands the proxy a merged configuration on
// every change.
package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxBody bounds one API response.
const maxBody = 64 << 20

type client struct {
	base    string
	token   string
	http    *http.Client
	timeout time.Duration
}

func newClient(apiServer, tokenFile, caFile string, timeout time.Duration) (*client, error) {
	u, err := url.Parse(apiServer)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("api_server %q is not a URL", apiServer)
	}
	c := &client{base: strings.TrimSuffix(apiServer, "/"), timeout: timeout}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile) //nolint:gosec // configured path
		if err != nil {
			return nil, fmt.Errorf("token_file: %w", err)
		}
		c.token = strings.TrimSpace(string(b))
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" && u.Scheme == "https" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // configured path
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file contains no certificates")
		}
		tc.RootCAs = pool
	}
	c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects not followed") }}
	return c, nil
}

// get fetches one API path into out.
func (c *client) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xproxy-ingress/1")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return fmt.Errorf("%s: response larger than %d bytes", path, maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		var st struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &st)
		return fmt.Errorf("%s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(st.Message))
	}
	return json.Unmarshal(body, out)
}

// Kubernetes object shapes, only the fields used.

type objectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`
}

type servicePort struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
}

type backend struct {
	Service *struct {
		Name string      `json:"name"`
		Port servicePort `json:"port"`
	} `json:"service"`
}

type httpPath struct {
	Path     string  `json:"path"`
	PathType string  `json:"pathType"`
	Backend  backend `json:"backend"`
}

type ingressRule struct {
	Host string `json:"host"`
	HTTP *struct {
		Paths []httpPath `json:"paths"`
	} `json:"http"`
}

type ingressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secretName"`
}

// Ingress is networking.k8s.io/v1 Ingress.
type Ingress struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		IngressClassName string        `json:"ingressClassName"`
		DefaultBackend   *backend      `json:"defaultBackend"`
		TLS              []ingressTLS  `json:"tls"`
		Rules            []ingressRule `json:"rules"`
	} `json:"spec"`
}

// Service is core/v1 Service (ports only).
type Service struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Ports []struct {
			Name       string `json:"name"`
			Port       int    `json:"port"`
			TargetPort any    `json:"targetPort"`
		} `json:"ports"`
	} `json:"spec"`
}

// EndpointSlice is discovery.k8s.io/v1 EndpointSlice.
type EndpointSlice struct {
	Metadata    objectMeta `json:"metadata"`
	AddressType string     `json:"addressType"`
	Endpoints   []struct {
		Addresses  []string `json:"addresses"`
		Conditions struct {
			Ready *bool `json:"ready"`
		} `json:"conditions"`
	} `json:"endpoints"`
	Ports []struct {
		Name     string `json:"name"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

// Secret is core/v1 Secret.
type Secret struct {
	Metadata objectMeta        `json:"metadata"`
	Type     string            `json:"type"`
	Data     map[string]string `json:"data"`
}

type list[T any] struct {
	Items []T `json:"items"`
}

func (c *client) ingresses(ctx context.Context, ns string) ([]Ingress, error) {
	var l list[Ingress]
	path := "/apis/networking.k8s.io/v1/ingresses"
	if ns != "" {
		path = "/apis/networking.k8s.io/v1/namespaces/" + ns + "/ingresses"
	}
	return l.Items, c.get(ctx, path, &l)
}

func (c *client) services(ctx context.Context, ns string) ([]Service, error) {
	var l list[Service]
	path := "/api/v1/services"
	if ns != "" {
		path = "/api/v1/namespaces/" + ns + "/services"
	}
	return l.Items, c.get(ctx, path, &l)
}

func (c *client) endpointSlices(ctx context.Context, ns string) ([]EndpointSlice, error) {
	var l list[EndpointSlice]
	path := "/apis/discovery.k8s.io/v1/endpointslices"
	if ns != "" {
		path = "/apis/discovery.k8s.io/v1/namespaces/" + ns + "/endpointslices"
	}
	return l.Items, c.get(ctx, path, &l)
}

func (c *client) gateways(ctx context.Context, ns string) ([]Gateway, error) {
	var l list[Gateway]
	path := "/apis/gateway.networking.k8s.io/v1/gateways"
	if ns != "" {
		path = "/apis/gateway.networking.k8s.io/v1/namespaces/" + ns + "/gateways"
	}
	return l.Items, c.get(ctx, path, &l)
}

func (c *client) httpRoutes(ctx context.Context, ns string) ([]HTTPRoute, error) {
	var l list[HTTPRoute]
	path := "/apis/gateway.networking.k8s.io/v1/httproutes"
	if ns != "" {
		path = "/apis/gateway.networking.k8s.io/v1/namespaces/" + ns + "/httproutes"
	}
	return l.Items, c.get(ctx, path, &l)
}

// errNotFound marks a list of a resource the cluster does not serve
// (the Gateway API CRDs are optional).
var errNotFound = errors.New("not found")

func isNotFound(err error) bool {
	return err != nil && (errors.Is(err, errNotFound) || strings.Contains(err.Error(), "HTTP 404"))
}

// watch opens a watch stream on path and calls fn for every event until
// ctx ends or the stream breaks. It uses a client without an overall
// timeout: the server ends the stream on its own schedule.
func (c *client) watch(ctx context.Context, path string, fn func(kind string)) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+sep+"watch=1&allowWatchBookmarks=true&timeoutSeconds=300", http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xproxy-ingress/1")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// No overall timeout (the server ends the stream on its schedule) but
	// the response headers must arrive within the request timeout, so a
	// black holed connection cannot hang the stream's loop.
	tr := c.http.Transport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = c.timeout
	wc := &http.Client{Transport: tr, CheckRedirect: c.http.CheckRedirect}
	resp, err := wc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("watch %s: HTTP %d", path, resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<30))
	for {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if ev.Type == "" {
			continue
		}
		fn(ev.Type)
	}
}

func (c *client) secret(ctx context.Context, ns, name string) (*Secret, error) {
	var s Secret
	if err := c.get(ctx, "/api/v1/namespaces/"+ns+"/secrets/"+name, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
