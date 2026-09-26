package intel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Feeds fetched over the network: a plain URL, a TAXII 2.1 collection, a MISP
// instance.
//
// A file is the base case and stays the simplest thing that works: somebody
// else's cron job writes it and the proxy notices. What a fetch adds is that the
// estate does not have to run that cron job -- and what it costs is a dependency
// on something reachable, which is why every rule below is about what happens
// when it is not.
//
//   - **A fetch that fails keeps the entries already loaded.** The same rule the
//     file path has, for the same reason: a feed being rewritten, or a TAXII
//     server having an afternoon, must not empty the policy. The failure is
//     counted and reported instead, because a list that has quietly stopped
//     updating is the failure mode worth alerting on.
//   - **The first fetch is different.** At start there is nothing to keep, so a
//     source that cannot be reached fails the load. A proxy that came up with an
//     empty list it believes is populated is the outcome this package exists to
//     prevent -- and unlike a stale list, this one is visible at start, which is
//     when somebody is watching.
//   - **Nothing is trusted about the size.** The body is bounded before it is
//     read, not after: a feed URL that answers with a terabyte is a feed URL
//     that would otherwise be this proxy's memory bound.
//   - **A fetch is a full fetch.** TAXII can be polled incrementally with
//     added_after, and this does not: a full fetch means the list always equals
//     the collection, so an indicator the publisher revoked disappears. An
//     incremental poller would accumulate withdrawn intelligence for ever, and
//     "the feed says to block it" would stop being checkable against the feed.

// Bounds on a fetch.
const (
	// DefaultFetchTimeout bounds one fetch, including every page of a
	// paginated TAXII collection.
	DefaultFetchTimeout = 60 * time.Second
	// maxPages bounds a paginated collection. A TAXII server that keeps
	// saying "more" is a server this proxy would follow for ever.
	maxPages = 128
)

// HTTPSpec is how a network source is reached: the credential, the TLS trust,
// and the bound on how long it may take.
type HTTPSpec struct {
	// Timeout bounds the whole fetch; 0 is DefaultFetchTimeout.
	Timeout time.Duration
	// Token is a bearer token, sent as "Authorization: Bearer <token>". For
	// MISP it is the API key and is sent bare, as MISP expects.
	Token string
	// Header and HeaderValue are one extra header, for the feeds whose
	// credential is neither of the above.
	Header, HeaderValue string
	// CAFile is the trust anchor for the server's certificate; empty means
	// the system roots.
	CAFile string
	// ServerName overrides the name verified in the certificate.
	ServerName string
	// Insecure and AllowInsecure together disable verification. Both are
	// needed, and it is refused for anything but a loopback address: a feed
	// fetched without verifying the server is a feed anything on the path can
	// write, and what it writes becomes this proxy's block list.
	Insecure, AllowInsecure bool
}

// TAXIISpec is a TAXII 2.1 collection to poll.
type TAXIISpec struct {
	// APIRoot is the API root URL, as the server's discovery document gives
	// it -- for example https://taxii.example/api1/.
	APIRoot string
	// Collection is the collection's id.
	Collection string
	// AddedAfter, when set, asks the server for objects added after this
	// timestamp. It is a floor on age rather than incremental state: every
	// fetch sends the same value, so the list is still the whole answer to
	// the same question.
	AddedAfter string
}

// MISPSpec is a MISP instance to search.
type MISPSpec struct {
	// BaseURL is the instance, for example https://misp.example.
	BaseURL string
	// Types narrows the attribute types asked for. Empty asks for the ones
	// this proxy can match on, which is the useful default: asking for
	// everything and discarding most of it makes the instance do work for
	// nothing.
	Types []string
	// Tags narrows by MISP tag, which is how an estate subscribes to part of
	// a sharing community rather than all of it.
	Tags []string
	// Published asks only for attributes of published events, which is MISP's
	// own boundary between a draft and intelligence.
	Published bool
	// Limit bounds the attributes asked for in one search; 0 lets the
	// instance decide.
	Limit int
}

// fetcher performs one source's fetch. It is built once per list so the HTTP
// client, and with it the connection pool and the TLS session cache, is reused
// across refreshes.
type fetcher struct {
	client *http.Client
	spec   HTTPSpec
	// etag and lastModified are the validators from the previous fetch, so an
	// unchanged feed costs a 304 rather than a download. Only the plain URL
	// form uses them: TAXII and MISP are queries rather than documents.
	etag, lastModified string
}

// timeout is the bound on one fetch.
func (f *fetcher) timeout() time.Duration {
	if f.spec.Timeout > 0 {
		return f.spec.Timeout
	}
	return DefaultFetchTimeout
}

// errNotModified says the server answered 304, so the entries already loaded
// are current. It is not a failure.
var errNotModified = errors.New("intel: not modified")

// newFetcher builds the HTTP client for a source.
func newFetcher(spec HTTPSpec) (*fetcher, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if spec.ServerName != "" {
		tc.ServerName = spec.ServerName
	}
	if spec.CAFile != "" {
		pem, err := os.ReadFile(spec.CAFile) //nolint:gosec // a configured path
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no certificate in it", spec.CAFile)
		}
		tc.RootCAs = pool
	}
	if spec.Insecure && spec.AllowInsecure {
		// Validated as loopback-only before we get here; see checkInsecure.
		tc.InsecureSkipVerify = true //nolint:gosec // double opt-in, loopback only, refused otherwise
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	return &fetcher{
		spec: spec,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:       tc,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				// One feed at a time per list: a refresh is serial and a pool
				// of idle connections to a server polled every ten minutes is
				// a pool that is always stale.
				MaxIdleConns:    2,
				IdleConnTimeout: 90 * time.Second,
			},
			// A feed that redirects is followed, but not off the host it was
			// configured as: a redirect to somewhere else is a feed URL that
			// has changed owner, and following it would mean this proxy's
			// block list comes from wherever the last hop said.
			CheckRedirect: sameHostRedirect,
		},
	}, nil
}

// sameHostRedirect allows a redirect within one host and refuses one that
// leaves it.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	first := via[0].URL
	if !strings.EqualFold(req.URL.Host, first.Host) {
		return fmt.Errorf("a feed redirected from %s to %s; a feed that changes host has changed owner", first.Host, req.URL.Host)
	}
	// And never down from https to http, which would hand the list to
	// anything on the path.
	if first.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("a feed redirected from https to %s", req.URL.Scheme)
	}
	return nil
}

// get performs one bounded request and returns the body.
func (f *fetcher) get(ctx context.Context, method, rawURL string, body io.Reader, accept string, conditional bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch {
	case f.spec.Token != "" && strings.Contains(strings.ToLower(accept), "taxii"):
		req.Header.Set("Authorization", "Bearer "+f.spec.Token)
	case f.spec.Token != "":
		// MISP sends the API key bare in Authorization, and a plain feed
		// behind a bearer token takes the Bearer form. Which one is decided
		// by the caller through the header below when it matters.
		req.Header.Set("Authorization", f.spec.Token)
	}
	if f.spec.Header != "" {
		req.Header.Set(f.spec.Header, f.spec.HeaderValue)
	}
	if conditional {
		if f.etag != "" {
			req.Header.Set("If-None-Match", f.etag)
		}
		if f.lastModified != "" {
			req.Header.Set("If-Modified-Since", f.lastModified)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()
	switch {
	case resp.StatusCode == http.StatusNotModified && conditional:
		return nil, errNotModified
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	// Bounded before it is read: a feed that answers with a terabyte would
	// otherwise be this proxy's memory bound.
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDocument {
		return nil, fmt.Errorf("%s: more than %d bytes", rawURL, MaxDocument)
	}
	if conditional {
		f.etag = resp.Header.Get("ETag")
		f.lastModified = resp.Header.Get("Last-Modified")
	}
	return data, nil
}

// fetchURL gets a plain feed document, conditionally.
func (f *fetcher) fetchURL(ctx context.Context, rawURL string) ([]byte, error) {
	return f.get(ctx, http.MethodGet, rawURL, nil, "", true)
}

// taxiiEnvelope is the part of a TAXII 2.1 envelope this reads. The objects are
// left as raw JSON so they can be handed to the STIX parser unchanged rather
// than round-tripped through a second struct.
type taxiiEnvelope struct {
	More    bool              `json:"more"`
	Next    string            `json:"next"`
	Objects []json.RawMessage `json:"objects"`
}

// fetchTAXII reads every page of a collection and returns one bundle.
//
// Paginated because a collection is larger than a response: the server says
// "more" and gives a cursor, and this follows it up to maxPages. A server that
// keeps saying more past that is one this proxy would follow for ever, so the
// fetch fails with the page count rather than continuing -- an operator can see
// a bound they have hit, and cannot see a loop.
func (f *fetcher) fetchTAXII(ctx context.Context, spec TAXIISpec) ([]byte, error) {
	root := strings.TrimRight(spec.APIRoot, "/")
	base := root + "/collections/" + url.PathEscape(spec.Collection) + "/objects/"
	const accept = "application/taxii+json;version=2.1"
	var objects []json.RawMessage
	next := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("%s: still paginating after %d pages", base, maxPages)
		}
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		if spec.AddedAfter != "" {
			q.Set("added_after", spec.AddedAfter)
		}
		if next != "" {
			q.Set("next", next)
		}
		u.RawQuery = q.Encode()
		data, err := f.get(ctx, http.MethodGet, u.String(), nil, accept, false)
		if err != nil {
			return nil, err
		}
		var env taxiiEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, fmt.Errorf("%s: not a TAXII envelope: %w", u, err)
		}
		objects = append(objects, env.Objects...)
		if len(objects) > MaxEntries {
			return nil, fmt.Errorf("%s: more than %d objects", base, MaxEntries)
		}
		// A server that says "more" without a cursor has nowhere to send us,
		// and one that repeats a cursor would loop; both end the fetch with
		// what has been collected.
		if !env.More || env.Next == "" || env.Next == next {
			break
		}
		next = env.Next
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("%s: the collection is empty", base)
	}
	// Reassembled as a bundle so that one STIX parser serves a file, a URL and
	// a collection -- rather than a second reader that could drift from it.
	return json.Marshal(map[string]any{"type": "bundle", "objects": objects})
}

// fetchMISP searches an instance for the attributes this proxy can match on.
func (f *fetcher) fetchMISP(ctx context.Context, spec MISPSpec) ([]byte, error) {
	base := strings.TrimRight(spec.BaseURL, "/") + "/attributes/restSearch"
	types := spec.Types
	if len(types) == 0 {
		// The useful default: asking for everything and discarding most of it
		// makes the instance do work for nothing, and a MISP search over two
		// hundred types is a search an operator waits for.
		types = matchableMISPTypes()
	}
	body := map[string]any{
		"returnFormat": "json",
		"type":         types,
		// Only what the publisher marked for detection, which is the same rule
		// the parser applies -- asked for here as well so the instance does not
		// send what would be discarded.
		"to_ids": true,
	}
	if spec.Published {
		body["published"] = true
	}
	if len(spec.Tags) > 0 {
		body["tags"] = spec.Tags
	}
	if spec.Limit > 0 {
		body["limit"] = spec.Limit
	}
	enc, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return f.get(ctx, http.MethodPost, base, strings.NewReader(string(enc)), "application/json", false)
}

// matchableMISPTypes is the attribute types this proxy can compare against
// traffic, which is what a search asks for by default.
func matchableMISPTypes() []string {
	return []string{
		"ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
		"domain", "hostname", "domain|ip",
		"url", "uri", "link",
		"md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256",
	}
}

// digestOf is how a fetched document is compared against the previous one, in
// place of the file modification time. A feed that answers identically has not
// changed, whatever its headers said.
func digestOf(data []byte) [32]byte { return sha256.Sum256(data) }
