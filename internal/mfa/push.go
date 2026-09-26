package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The second factor that is not typed: a notification somebody approves on a
// device they already carry.
//
// It is the factor people actually use, and it is also the one with an attack
// of its own. A one-time code is only as good as the user's typing; a push is
// only as good as the user's attention, and an attacker who has the first
// factor can send push after push until somebody taps approve to stop their
// phone buzzing. Everything below is shaped by that:
//
//   - One request in flight per user. A second attempt while one is waiting is
//     refused and sends nothing, so a stolen password cannot be turned into a
//     queue of notifications.
//   - A bound on pushes per user per window, which is the fatigue attack's
//     rate. Over it, the attempt is refused and counted, and no push is sent.
//   - A number the user has to recognise. The proxy generates it, tells the
//     user through whatever prompt the protocol has, and sends it with the
//     request; a person approving a notification they did not cause sees a
//     number that matches nothing they are looking at.
//   - Fail closed, in every way it can fail: a timeout, a refusal from the
//     service, an answer whose nonce is not the one asked about, a reply this
//     proxy cannot read. A second factor that passes when the service is
//     unreachable is not a second factor.

// Bounds and defaults for the push factor.
const (
	// DefaultPushTimeout is how long a person has to answer. Long enough to
	// find a phone, short enough that a session is not held open on the
	// chance somebody eventually will.
	DefaultPushTimeout = 60 * time.Second
	// DefaultPushPoll is how often a service that answers "pending" is asked
	// again. No new notification is sent by a poll.
	DefaultPushPoll = 2 * time.Second
	// DefaultPushPerWindow and DefaultPushWindow bound the notifications one
	// user can be sent.
	DefaultPushPerWindow = 3
	DefaultPushWindow    = 5 * time.Minute
	// maxPushBody bounds a reply. A service that answers with a megabyte is a
	// service this proxy would otherwise read a megabyte from.
	maxPushBody = 64 << 10
	// maxPushUsers bounds the table of what each user has been sent.
	maxPushUsers = 10000
)

// Push failures, separated because they mean different things to an operator:
// a refusal is the user saying no, a timeout is nobody answering, and the rest
// is the service or the network.
var (
	// ErrPushDenied is the user answering no.
	ErrPushDenied = errors.New("mfa: the approval was refused")
	// ErrPushTimeout is nobody answering in time.
	ErrPushTimeout = errors.New("mfa: nobody answered the approval request")
	// ErrPushThrottled is a user who has been sent as many notifications as
	// the window allows, which is the fatigue attack being refused.
	ErrPushThrottled = errors.New("mfa: too many approval requests for this user")
	// ErrPushPending is a request already waiting for this user.
	ErrPushPending = errors.New("mfa: an approval request for this user is already waiting")
	// ErrPushUnreachable is the service failing to answer usefully. It is
	// separate from a denial because one is a decision and the other is an
	// outage, and an operator needs to tell them apart.
	ErrPushUnreachable = errors.New("mfa: the approval service could not be reached")
)

// PushConfig is how the approval service is reached and how hard it may be
// leaned on.
type PushConfig struct {
	// URL is the endpoint a request is POSTed to. https, and a loopback
	// http:// for a development instance.
	URL string
	// Timeout bounds one approval, including every poll of a service that
	// answers "pending".
	Timeout time.Duration
	// Poll is how often a pending request is asked about.
	Poll time.Duration
	// Token is the credential, sent as a bearer token. Header and
	// HeaderValue are one extra header for the services whose credential is
	// neither.
	Token       string
	Header      string
	HeaderValue string
	// CAFile is the trust anchor for the service's certificate, empty for
	// the system roots; ServerName overrides the name verified in it.
	CAFile     string
	ServerName string
	// Insecure and AllowInsecure together skip verification, and are refused
	// for anything but a loopback address: an approval service nobody
	// authenticated is an approval service anything on the path can answer
	// for.
	Insecure, AllowInsecure bool
	// PerWindow and Window bound the notifications one user may be sent.
	PerWindow int
	Window    time.Duration
	// Numbers asks for a number the user has to recognise. Default true.
	Numbers *bool
}

// Pusher asks an approval service about one authentication at a time per user.
type Pusher struct {
	cfg    PushConfig
	client *http.Client

	// Sent, Approved, Denied, Failed and Throttled are what an operator
	// watches. Throttled climbing is the fatigue attack in progress.
	Sent, Approved, Denied, Failed, Throttled atomic.Uint64

	mu      sync.Mutex
	pending map[string]bool        // users with a request in flight
	recent  map[string][]time.Time // notifications sent per user
}

// numbers reports whether a number has to be recognised.
func (c PushConfig) numbers() bool { return c.Numbers == nil || *c.Numbers }

// NewPusher builds the client for an approval service.
func NewPusher(cfg PushConfig) (*Pusher, error) {
	if cfg.URL == "" {
		return nil, errors.New("mfa push: url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("mfa push: url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("mfa push: url: must be an http:// or https:// URL")
	}
	if u.Host == "" {
		return nil, errors.New("mfa push: url: no host")
	}
	if err := checkPushInsecure(u.Hostname(), cfg); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultPushTimeout
	}
	if cfg.Poll <= 0 {
		cfg.Poll = DefaultPushPoll
	}
	if cfg.PerWindow <= 0 {
		cfg.PerWindow = DefaultPushPerWindow
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultPushWindow
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ServerName != "" {
		tc.ServerName = cfg.ServerName
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // a configured path
		if err != nil {
			return nil, fmt.Errorf("mfa push: ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("mfa push: ca_file %s: no certificate in it", cfg.CAFile)
		}
		tc.RootCAs = pool
	}
	if cfg.Insecure && cfg.AllowInsecure {
		// Loopback only; checked above.
		tc.InsecureSkipVerify = true //nolint:gosec // double opt-in, loopback only, refused otherwise
	}
	return &Pusher{
		cfg:     cfg,
		pending: map[string]bool{},
		recent:  map[string][]time.Time{},
		client: &http.Client{
			// No timeout on the client: the bound is the context, which covers
			// the whole approval rather than each request of it.
			Transport: &http.Transport{
				TLSClientConfig:     tc,
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				MaxIdleConns:        4,
				IdleConnTimeout:     90 * time.Second,
			},
			// A redirect is refused rather than followed: an approval service
			// that can redirect is an approval service whose answer can come
			// from somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("an approval service must not redirect")
			},
		},
	}, nil
}

// checkPushInsecure refuses verification-skipping anywhere but the loopback.
func checkPushInsecure(host string, cfg PushConfig) error {
	if !cfg.Insecure {
		return nil
	}
	if !cfg.AllowInsecure {
		return errors.New("mfa push: insecure needs allow_insecure as well, so skipping verification is two decisions rather than one")
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("mfa push: insecure is set for %s, which is not a loopback address: an approval service nobody authenticated can be answered for by anything on the path", host)
}

// PushSubject is who is authenticating and where, which is what a person needs
// to see to decide whether the request is theirs.
type PushSubject struct {
	User     string
	Listener string
	Protocol string
	ClientIP string
}

// PushRequest is one approval in flight. Number is what the user has to
// recognise, and is empty when numbers are off.
type PushRequest struct {
	Number string
	nonce  string
	user   string
}

// Prompt is what to show the user: the number to look for, or a plain
// instruction when numbers are off.
func (r *PushRequest) Prompt() string {
	if r == nil {
		return ""
	}
	if r.Number == "" {
		return "Approve the sign-in request on your device."
	}
	return "Approve the sign-in request showing " + r.Number + " on your device."
}

// Begin takes the user's slot and the number, before anything is sent: the
// fatigue bounds are applied here, so a refused attempt costs the user no
// notification at all.
func (p *Pusher) Begin(user string, now time.Time) (*PushRequest, error) {
	if p == nil {
		return nil, ErrPushUnreachable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending[user] {
		p.Throttled.Add(1)
		return nil, ErrPushPending
	}
	// Only the notifications inside the window count. A user who was pushed
	// three times yesterday starts today with a clean slate.
	keep := p.recent[user][:0]
	for _, t := range p.recent[user] {
		if now.Sub(t) < p.cfg.Window {
			keep = append(keep, t)
		}
	}
	p.recent[user] = keep
	if len(keep) >= p.cfg.PerWindow {
		p.Throttled.Add(1)
		return nil, ErrPushThrottled
	}
	if len(p.recent) > maxPushUsers {
		// The table is bounded, and what is dropped is the history rather than
		// the decision: a user whose record is dropped is pushed again, never
		// let through.
		p.recent = map[string][]time.Time{user: keep}
	}
	p.recent[user] = append(keep, now)
	p.pending[user] = true
	req := &PushRequest{nonce: newNonce(), user: user}
	if p.cfg.numbers() {
		req.Number = twoDigits()
	}
	return req, nil
}

// Done releases the user's slot. Every Begin that returned a request has to
// reach it, whatever happened in between.
func (p *Pusher) Done(r *PushRequest) {
	if p == nil || r == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, r.user)
}

// pushAnswer is what the service replies with, in both shapes: the answer to
// the request, or that it is still waiting for the user.
type pushAnswer struct {
	Nonce  string `json:"nonce"`
	Result string `json:"result"` // approved, denied, pending
	Detail string `json:"detail"`
}

// Wait sends the request and waits for the answer, bounded by the timeout.
// Every failure is a refusal: what a second factor must never do is pass
// because the thing that checks it did not answer.
func (p *Pusher) Wait(ctx context.Context, r *PushRequest, sub PushSubject) error {
	if p == nil || r == nil {
		return ErrPushUnreachable
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	body, err := json.Marshal(struct {
		Nonce       string `json:"nonce"`
		User        string `json:"user"`
		Listener    string `json:"listener"`
		Protocol    string `json:"protocol"`
		ClientIP    string `json:"client_ip"`
		Number      string `json:"number,omitempty"`
		RequestedAt string `json:"requested_at"`
	}{r.nonce, sub.User, sub.Listener, sub.Protocol, sub.ClientIP, r.Number, time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return ErrPushUnreachable
	}
	p.Sent.Add(1)
	ans, err := p.ask(ctx, http.MethodPost, p.cfg.URL, body)
	if err == nil {
		err = r.checkNonce(ans)
	}
	for err == nil && ans.Result == "pending" {
		// A service that answers immediately is asked again, without sending a
		// second notification: the POST is the notification, a poll is a
		// question about it.
		select {
		case <-ctx.Done():
			p.Failed.Add(1)
			return ErrPushTimeout
		case <-time.After(p.cfg.Poll):
		}
		ans, err = p.ask(ctx, http.MethodGet, p.pollURL(r), nil)
		if err == nil {
			err = r.checkNonce(ans)
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		p.Failed.Add(1)
		return ErrPushTimeout
	case err != nil:
		p.Failed.Add(1)
		return fmt.Errorf("%w: %w", ErrPushUnreachable, err)
	}
	switch ans.Result {
	case "approved":
		p.Approved.Add(1)
		return nil
	case "denied":
		p.Denied.Add(1)
		return ErrPushDenied
	default:
		// An answer this proxy cannot read is not an approval.
		p.Failed.Add(1)
		return fmt.Errorf("%w: the service answered %q", ErrPushUnreachable, clipResult(ans.Result))
	}
}

// pollURL is the request's own URL: the configured endpoint with the nonce,
// which is how a service is asked about a request rather than sent a new one.
func (p *Pusher) pollURL(r *PushRequest) string {
	sep := "?"
	if strings.Contains(p.cfg.URL, "?") {
		sep = "&"
	}
	return p.cfg.URL + sep + "nonce=" + url.QueryEscape(r.nonce)
}

// ask performs one bounded request and reads the answer, which has to be about
// the request that was made: a reply whose nonce is somebody else's is not an
// answer, and taking it as one would let a service (or anything that can
// answer for it) approve a session nobody asked about.
func (p *Pusher) ask(ctx context.Context, method, rawURL string, body []byte) (pushAnswer, error) {
	var out pushAnswer
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return out, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}
	if p.cfg.Header != "" {
		req.Header.Set(p.cfg.Header, p.cfg.HeaderValue)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return out, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%s answered %s", method, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPushBody+1))
	if err != nil {
		return out, err
	}
	if len(data) > maxPushBody {
		return out, fmt.Errorf("the answer is larger than %d bytes", maxPushBody)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("the answer is not the JSON this expects: %w", err)
	}
	return out, nil
}

// checkNonce is the nonce comparison, split out so the caller of ask can be
// read without it and so it cannot be forgotten in one of the two places.
func (r *PushRequest) checkNonce(ans pushAnswer) error {
	if ans.Nonce != r.nonce {
		return fmt.Errorf("the answer is about %q, not the request that was made", clipResult(ans.Nonce))
	}
	return nil
}

// newNonce is the identifier of one approval: 128 bits, so a service cannot be
// tricked into answering about a request somebody guessed.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on any platform this runs on, and a nonce
		// that is not random is a nonce nobody should rely on, so this is a
		// value no service will match rather than a weak one.
		return "unavailable"
	}
	return hex.EncodeToString(b)
}

// twoDigits is the number the user has to recognise. Two digits is what the
// devices show, and guessing one in a hundred is not the attack this defends
// against: the attack is a person tapping approve without looking.
func twoDigits() string {
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%02d", n.Int64())
}

// clipResult bounds what a service's text can put in a log line.
func clipResult(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}
