package mgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks to the management API over the Unix socket.
type Client struct {
	http *http.Client
}

// NewClient creates a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
			DisableKeepAlives: true,
		},
	}}
}

func (c *Client) do(method, path string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://xproxy"+path, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("management API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		var r result
		if json.Unmarshal(body, &r) == nil && r.Error != "" {
			return fmt.Errorf("%s", r.Error)
		}
		return fmt.Errorf("management API: HTTP %d", resp.StatusCode)
	}
	switch o := out.(type) {
	case nil:
	case *[]byte:
		*o = body
	default:
		return json.Unmarshal(body, out)
	}
	return nil
}

// Status fetches /v1/status.
func (c *Client) Status() (*Status, error) {
	var s Status
	return &s, c.do("GET", "/v1/status", &s)
}

// Raw fetches a GET endpoint and returns the body.
func (c *Client) Raw(path string) ([]byte, error) {
	var b []byte
	return b, c.do("GET", path, &b)
}

// Post triggers an action endpoint.
func (c *Client) Post(path string) error {
	return c.do("POST", path, nil)
}
