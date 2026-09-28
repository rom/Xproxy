package ntp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	wire "github.com/rom/xproxy/internal/ntp"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
)

// The relay's own NTS association with the time source.
//
// Terminating a client's NTS says what happens on this side of the relay. This
// says what happens on the other side: instead of asking the source in plain
// NTP, the relay holds an association of its own -- its own key establishment
// with the source's key establishment server, its own cookies, its own
// authenticator on every request, and verification of every answer.
//
// What this costs is worth being plain about, and the configuration reference
// says it too: there is no end-to-end authentication between the client and the
// source any more. The client authenticates to this relay and this relay
// authenticates to the source. What it buys is a relay that can compare, police
// and log what the source says while both halves are still authenticated, which
// a pass-through relay cannot do at all.

// The bounds of the association.
const (
	// cookieTarget is the depth of the cookie pool this keeps. One is spent per
	// exchange and one comes back, so the pool only shrinks when answers are
	// lost; the placeholders on each request top it back up.
	cookieTarget = ke.CookiesPerResponse
	// establishRetry is how long a failed key establishment waits. A source
	// whose key establishment server is down is a source this relay cannot ask
	// for the time, and hammering it would not change that.
	establishRetry = 30 * time.Second
)

// The refusals this adds.
const (
	// ReasonSourceNotReady is a request that arrived before this relay held
	// keys with the source. It is dropped rather than sent in plain NTP: a
	// relay that quietly downgraded its own request would be doing the thing
	// this configuration exists to prevent, and a time client retries.
	ReasonSourceNotReady = "nts_source_not_ready"
	// ReasonSourceUnverified is an answer from the source whose authenticator
	// did not verify, or which did not echo the identifier the request carried.
	ReasonSourceUnverified = "nts_source_unverified"
)

// originator holds the association.
type originator struct {
	host     proxy.Host
	listener string
	client   *ke.Client
	// refreshBelow is the cookie count at which keys are established again.
	refreshBelow int

	mu sync.Mutex
	// keys and cookies are the association. There is no algorithm here
	// because there is only one: the client half offers AEAD_AES_SIV_CMAC_256
	// alone and refuses a response that chose anything else, so a field
	// carrying which one was agreed would have one value.
	keys    *ke.Keys
	cookies [][]byte
	// establishing is set while one exchange is in flight, so a burst of
	// requests to a relay with no keys draws one key establishment rather than
	// one per request.
	establishing bool
	// nextTry is when a failed establishment may be tried again.
	nextTry time.Time
	now     func() time.Time

	// Established and Verified are for the status view and the tests.
	Established, Verified atomic.Uint64
}

// compileOriginator builds the association from the configuration.
func compileOriginator(host proxy.Host, listener string, c *config.NTPSourceNTS, secrets *keysource.Resolver) (*originator, error) {
	if c == nil || c.KEAddress == "" {
		return nil, errors.New("ntp: nts.source needs a ke_address")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.ServerName}
	if c.CAFile != "" {
		pem, err := secrets.Bytes(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ntp: nts.source.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ntp: nts.source.ca_file %s: no certificates in it", c.CAFile)
		}
		tc.RootCAs = pool
	}
	if c.CertFile != "" || c.KeyFile != "" {
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, errors.New("ntp: nts.source needs both cert_file and key_file, or neither")
		}
		pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("ntp: nts.source client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return &originator{
		host: host, listener: listener,
		client:       &ke.Client{Address: c.KEAddress, TLS: tc, Timeout: c.Timeout.D()},
		refreshBelow: c.SourceRefreshBelow(),
		now:          time.Now,
	}, nil
}

// sourceSession is what one outgoing request needs remembered.
type sourceSession struct {
	keys *ke.Keys
	// uniqueID is what the answer has to echo. Without it an answer to another
	// of this relay's requests would verify: the keys are the same for the whole
	// association, and only the identifier ties an answer to a question.
	uniqueID []byte
}

// protect wraps a header as an NTS-protected request.
//
// header is the time packet as it will go on the wire before the NTS fields:
// forty-eight octets and nothing else, because the fields this adds have to be
// the last thing in the packet and a client's own MAC or extension fields are
// not this relay's to forward.
func (o *originator) protect(header []byte) ([]byte, *sourceSession, error) {
	if len(header) < wire.HeaderLen {
		return nil, nil, errors.New("ntp: a request shorter than a header cannot be protected")
	}
	cookie, want, keys, ok := o.take()
	if !ok {
		return nil, nil, errors.New("ntp: no cookies for the time source yet")
	}
	uid, err := wire.NTSUniqueIDField()
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, 0, wire.HeaderLen+128)
	out = append(out, header[:wire.HeaderLen]...)
	out = append(out, uid.Bytes()...)
	out = append(out, wire.NTSCookieField(cookie).Bytes()...)
	for i := 0; i < want; i++ {
		// A placeholder is the size of a cookie so the request is as large as
		// the answer it asks for. That is what stops this being an amplifier --
		// and the relay is the client here, so it is the relay's own request
		// that has to be the honest size.
		out = append(out, wire.NTSPlaceholderField(len(cookie)).Bytes()...)
	}
	out, err = wire.SealNTS(out, keys.C2S, nil)
	if err != nil {
		return nil, nil, err
	}
	return out, &sourceSession{keys: keys, uniqueID: uid.Body}, nil
}

// take spends a cookie and says how many replacements to ask for.
func (o *originator) take() (cookie []byte, placeholders int, keys *ke.Keys, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.keys == nil || len(o.cookies) == 0 {
		return nil, 0, nil, false
	}
	cookie = o.cookies[0]
	o.cookies = o.cookies[1:]
	// One replacement for the cookie just spent comes back without asking; the
	// placeholders are what tops the pool back up after a lost answer.
	if want := cookieTarget - len(o.cookies) - 1; want > 0 {
		placeholders = want
		if placeholders > wire.MaxNTSCookies-1 {
			placeholders = wire.MaxNTSCookies - 1
		}
	}
	return cookie, placeholders, o.keys, true
}

// verify checks the source's answer and keeps the cookies it carried.
func (o *originator) verify(pkt *wire.Packet, se *sourceSession) error {
	fields := pkt.NTS()
	if len(se.uniqueID) > 0 && !equalBytes(fields.UniqueID, se.uniqueID) {
		// The keys are the same for every exchange in this association, so an
		// answer to another of this relay's requests would verify. The
		// identifier is what makes an answer an answer to this question.
		return errors.New("ntp: the answer does not echo the identifier the request carried")
	}
	inner, err := pkt.OpenNTS(se.keys.S2C)
	if err != nil {
		return err
	}
	fresh := wire.NTSCookies(inner)
	if len(fresh) == 0 {
		// Not a refusal: an answer with no replacement cookie is a server being
		// stingy rather than a server being wrong, and the pool has the
		// placeholders and the refresh below to recover from it.
		o.host.Counters().NTPNTSSourceVerified.Add(1)
		o.Verified.Add(1)
		return nil
	}
	o.mu.Lock()
	for _, c := range fresh {
		if len(o.cookies) >= cookieTarget*2 {
			break
		}
		o.cookies = append(o.cookies, append([]byte(nil), c...))
	}
	o.mu.Unlock()
	o.host.Counters().NTPNTSSourceVerified.Add(1)
	o.Verified.Add(1)
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// low says whether the pool needs topping up with a fresh key establishment.
func (o *originator) low() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.keys == nil || len(o.cookies) < o.refreshBelow
}

// ensure establishes keys when there are none or too few.
//
// It runs in the background because a key establishment is a TLS handshake and
// the caller is a packet path: a request that waited for one would be a client
// waiting seconds for the time, and a client that gets no answer asks again.
func (o *originator) ensure() {
	o.mu.Lock()
	if o.establishing || o.now().Before(o.nextTry) {
		o.mu.Unlock()
		return
	}
	o.establishing = true
	o.mu.Unlock()
	go func() {
		defer safe.Guard("ntp nts key establishment")
		o.establish()
	}()
}

func (o *originator) establish() {
	est, err := o.client.Establish(context.Background())
	o.mu.Lock()
	o.establishing = false
	if err != nil {
		o.nextTry = o.now().Add(establishRetry)
		o.mu.Unlock()
		o.host.Counters().NTPNTSSourceFailed.Add(1)
		o.host.Logs().Error.Warn("ntp could not establish NTS keys with the time source",
			"listener", o.listener, "error", err.Error())
		return
	}
	o.keys = est.Keys
	o.cookies = append(o.cookies[:0:0], est.Cookies...)
	o.nextTry = time.Time{}
	o.mu.Unlock()
	o.host.Counters().NTPNTSSourceEstablished.Add(1)
	o.Established.Add(1)
	if est.Server != "" || est.HasPort {
		// Reported and not followed. Where this relay sends time traffic is the
		// estate's decision -- allow_servers and the upstream pool -- and a key
		// establishment server that named somewhere else would otherwise be
		// moving it.
		o.host.Logs().Security.Info("ntp: the source's key establishment named another time server",
			"listener", o.listener, "server", est.Server, "port", est.Port)
	}
}

// keep establishes keys at start and watches the pool.
//
// The interval is short because what it watches is cheap to check and the thing
// it prevents is expensive: a relay whose cookies ran out stops asking for the
// time, and nothing about that looks like a key problem from the outside.
func (o *originator) keep(done <-chan struct{}) {
	defer safe.Guard("ntp nts key keeper")
	o.ensure()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			if o.low() {
				o.ensure()
			}
		}
	}
}
