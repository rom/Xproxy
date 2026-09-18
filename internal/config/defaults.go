package config

import (
	"os"
	"strings"
	"time"
)

// Default values. They are deliberately conservative: an operator has to
// raise a limit on purpose, never lower one by accident.
const (
	DefaultMaxHeaderBytes        = 64 << 10
	DefaultMaxBodyBytes          = 10 << 20
	DefaultMaxURILength          = 8192
	DefaultReadHeaderTimeout     = 10 * time.Second
	DefaultReadTimeout           = 60 * time.Second
	DefaultWriteTimeout          = 60 * time.Second
	DefaultIdleTimeout           = 120 * time.Second
	DefaultMaxConnections        = 65536
	DefaultMaxConnectionsPerIP   = 256
	DefaultMaxConcurrentRequests = 16384
	DefaultMaxTarpits            = 1024
	DefaultShutdownTimeout       = 30 * time.Second

	DefaultUpstreamConnect        = 5 * time.Second
	DefaultUpstreamResponseHeader = 30 * time.Second
	DefaultUpstreamIdle           = 90 * time.Second
	DefaultUpstreamTotal          = 5 * time.Minute
	DefaultMaxIdleConnsPerHost    = 64
	DefaultRetries                = 1

	DefaultHealthInterval  = 5 * time.Second
	DefaultHealthTimeout   = 2 * time.Second
	DefaultHealthyCount    = 2
	DefaultUnhealthyCount  = 3
	DefaultHealthCheckPath = "/"
	// DefaultHealthMaxConcurrent bounds health probes in flight per pool.
	DefaultHealthMaxConcurrent = 32

	DefaultAffinityCookie = "XPSESS"
	DefaultAffinityTTL    = time.Hour

	DefaultOutlierFailures  = 5
	DefaultOutlierBaseTime  = 30 * time.Second
	DefaultOutlierMaxEjectP = 50

	DefaultTarpitDelay = 10 * time.Second

	DefaultBanMaxEntries  = 100000
	DefaultBanEscalation  = 2.0
	DefaultBanMaxDuration = 24 * time.Hour

	DefaultWAFRequestBodyLimit  = 1 << 20
	DefaultWAFResponseBodyLimit = 512 << 10
	DefaultCRSParanoia          = 1
	DefaultCRSInbound           = 5
	DefaultCRSOutbound          = 4

	DefaultLogDirectory = "/var/log/xproxy"
	DefaultLogLevel     = "info"
	DefaultSocketMode   = "0660"
)

// applyDefaults fills zero values with their documented defaults. It must be
// idempotent.
func applyDefaults(c *Config) {
	ingressDefaults(c)
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	s := &c.Server
	if s.ShutdownTimeout == 0 {
		s.ShutdownTimeout = Duration(DefaultShutdownTimeout)
	}
	l := &s.Limits
	setInt(&l.MaxHeaderBytes, DefaultMaxHeaderBytes)
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = DefaultMaxBodyBytes
	}
	setInt(&l.MaxURILength, DefaultMaxURILength)
	setDur(&l.ReadHeaderTimeout, DefaultReadHeaderTimeout)
	setDur(&l.ReadTimeout, DefaultReadTimeout)
	setDur(&l.WriteTimeout, DefaultWriteTimeout)
	setDur(&l.IdleTimeout, DefaultIdleTimeout)
	setInt(&l.MaxConnections, DefaultMaxConnections)
	setInt(&l.MaxConnectionsPerIP, DefaultMaxConnectionsPerIP)
	setInt(&l.MaxConcurrentRequests, DefaultMaxConcurrentRequests)
	setInt(&l.MaxTarpits, DefaultMaxTarpits)

	for i := range s.Listeners {
		setStr(&s.Listeners[i].Kind, "http")
		if t := s.Listeners[i].TCP; t != nil {
			setDur(&t.IdleTimeout, 10*time.Minute)
			setInt(&t.MaxConnections, 10000)
			setDur(&t.QUICIdleTimeout, 30*time.Second)
		}
		if f := s.Listeners[i].Forward; f != nil {
			if len(f.Ports) == 0 {
				f.Ports = []int{80, 443}
			}
			setDur(&f.ConnectTimeout, 10*time.Second)
			setDur(&f.IdleTimeout, 10*time.Minute)
			setInt(&f.MaxTunnels, 10000)
			if f.MaxResponseBytes == 0 {
				f.MaxResponseBytes = 64 << 20
			}
			if f.Auth != nil {
				setStr(&f.Auth.Realm, "proxy")
			}
		}
		if d := s.Listeners[i].DNS; d != nil {
			setDur(&d.Timeout, 2*time.Second)
			setStr(&d.BlockAction, "nxdomain")
			setStr(&d.SinkholeIPv4, "0.0.0.0")
			setStr(&d.SinkholeIPv6, "::")
			if d.Cache == nil {
				d.Cache = &DNSCache{}
			}
			setStr(&d.DoHPath, "/dns-query")
			setInt(&d.Cache.MaxEntries, 10000)
			setDur(&d.Cache.MinTTL, 5*time.Second)
			setDur(&d.Cache.MaxTTL, time.Hour)
			if d.Cache.NegativeTTL == 0 {
				d.Cache.NegativeTTL = Duration(60 * time.Second)
			}
			setInt(&d.MaxInFlight, 1024)
			if d.RateLimit != nil {
				if d.RateLimit.QPS == 0 {
					d.RateLimit.QPS = 50
				}
				setInt(&d.RateLimit.Burst, 100)
			}
		}
		ln := &s.Listeners[i]
		if ln.Kind == "tcp" || ln.Kind == "dns" {
			// No HTTP protocol defaults on a non-HTTP listener; an
			// encrypted dns listener still gets the TLS defaults.
			if ln.Kind == "dns" && ln.TLS != nil {
				setStr(&ln.TLS.MinVersion, "1.2")
				setStr(&ln.TLS.ClientAuth, "none")
			}
			continue
		}
		if len(ln.Protocols) == 0 {
			switch {
			case ln.Kind == "forward" && ln.TLS == nil:
				ln.Protocols = []Protocol{ProtocolH1}
			case ln.TLS != nil:
				ln.Protocols = []Protocol{ProtocolH1, ProtocolH2}
			default:
				ln.Protocols = []Protocol{ProtocolH1}
			}
		}
		if ln.TLS != nil {
			if ln.TLS.MinVersion == "" {
				ln.TLS.MinVersion = "1.2"
			}
			if ln.TLS.ClientAuth == "" {
				ln.TLS.ClientAuth = "none"
			}
		}
		hasH3 := false
		for _, p := range ln.Protocols {
			if p == ProtocolH3 {
				hasH3 = true
			}
		}
		if hasH3 {
			if ln.H3 == nil {
				ln.H3 = &H3{}
			}
			setInt(&ln.H3.MaxStreams, 100)
			setStr(&ln.H3.ValidateAddresses, "always")
			setDur(&ln.H3.AltSvcMaxAge, 24*time.Hour)
		}
	}

	setInt(&c.Management.HistoryKeep, 20)
	for _, o := range []*OTLPExport{c.Logging.OTLP, tracingOTLP(c.Tracing)} {
		if o == nil {
			continue
		}
		setDur(&o.Timeout, 10*time.Second)
		setStr(&o.ServiceName, "xproxy")
		setInt(&o.Batch, 512)
		setDur(&o.Interval, 5*time.Second)
		setInt(&o.Queue, 8192)
	}
	for i := range c.Server.Listeners {
		if t := c.Server.Listeners[i].TLS; t != nil && t.OCSPStapling != nil {
			setDur(&t.OCSPStapling.Timeout, 5*time.Second)
			setDur(&t.OCSPStapling.Refresh, time.Hour)
		}
	}
	if c.Management.SocketMode == "" {
		c.Management.SocketMode = DefaultSocketMode
	}

	lg := &c.Logging
	if lg.Directory == "" {
		lg.Directory = DefaultLogDirectory
	}
	if lg.Level == "" {
		lg.Level = DefaultLogLevel
	}
	setStr(&lg.Access.File, "access.log")
	setStr(&lg.Error.File, "error.log")
	setStr(&lg.Security.File, "security.log")
	setStr(&lg.Audit.File, "audit.log")
	for _, s := range []*LogStream{&lg.Access, &lg.Error, &lg.Security, &lg.Audit} {
		if len(s.Sinks) == 0 {
			s.Sinks = []string{"file"}
		}
		setStr(&s.Format, "json")
	}
	if j := lg.Journald; j != nil {
		setStr(&j.Socket, "/run/systemd/journal/socket")
		setStr(&j.Identifier, "xproxy")
	}
	if sl := lg.Syslog; sl != nil {
		setStr(&sl.Network, "unix")
		if sl.Address == "" && sl.Network == "unix" {
			sl.Address = "/dev/log"
		}
		if sl.Format == "" {
			if sl.Network == "unix" {
				sl.Format = "rfc3164"
			} else {
				sl.Format = "rfc5424"
			}
		}
		setStr(&sl.Facility, "local0")
		setStr(&sl.AppName, "xproxy")
		setInt(&sl.QueueSize, 8192)
	}
	if r := lg.Redaction; r != nil {
		if len(r.Streams) == 0 {
			r.Streams = []string{"access", "security", "error"}
		}
		setStr(&r.ClientIP, "truncate")
		setStr(&r.UserAgent, "keep")
		setStr(&r.Referer, "origin")
		setStr(&r.Claims, "hash")
	}

	for i := range c.RateLimits {
		rl := &c.RateLimits[i]
		setStr(&rl.Key, "client_ip")
		setStr(&rl.Action, "reject")
		if rl.Burst == 0 && rl.Rate > 0 {
			rl.Burst = int(rl.Rate)
			if rl.Burst < 1 {
				rl.Burst = 1
			}
		}
		setDur(&rl.TarpitDelay, DefaultTarpitDelay)
	}

	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		setStr(&u.Balancer, "round_robin")
		setStr(&u.Scheme, "http")
		setDur(&u.Timeouts.Connect, DefaultUpstreamConnect)
		setDur(&u.Timeouts.ResponseHeader, DefaultUpstreamResponseHeader)
		setDur(&u.Timeouts.Idle, DefaultUpstreamIdle)
		setDur(&u.Timeouts.Total, DefaultUpstreamTotal)
		setInt(&u.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
		if u.Retries == nil {
			r := DefaultRetries
			u.Retries = &r
		}
		if cb := u.CircuitBreaker; cb != nil {
			setInt(&cb.ConsecutiveFailures, 5)
			setDur(&cb.OpenFor, 10*time.Second)
			setInt(&cb.HalfOpenRequests, 1)
		}
		if q := u.Queue; q != nil {
			setInt(&q.Size, 100)
			setDur(&q.Timeout, time.Second)
		}
		if u.Balancer == "hash" {
			setStr(&u.HashOn, "client_ip")
		}
		if u.TLS != nil {
			setStr(&u.TLS.MinVersion, "1.2")
		}
		for j := range u.Endpoints {
			setInt(&u.Endpoints[j].Weight, 1)
		}
		if hc := u.HealthCheck; hc != nil {
			setStr(&hc.Type, "http")
			setStr(&hc.Path, DefaultHealthCheckPath)
			setDur(&hc.Interval, DefaultHealthInterval)
			setDur(&hc.Timeout, DefaultHealthTimeout)
			setInt(&hc.HealthyThreshold, DefaultHealthyCount)
			setInt(&hc.UnhealthyThreshold, DefaultUnhealthyCount)
			setInt(&hc.MaxConcurrent, DefaultHealthMaxConcurrent)
			if len(hc.ExpectedStatus) == 0 {
				hc.ExpectedStatus = []int{200}
			}
		}
		if a := u.Affinity; a != nil {
			setStr(&a.CookieName, DefaultAffinityCookie)
			setDur(&a.TTL, DefaultAffinityTTL)
		}
		if o := u.OutlierEjection; o != nil {
			setInt(&o.ConsecutiveFailures, DefaultOutlierFailures)
			setDur(&o.BaseEjectionTime, DefaultOutlierBaseTime)
			setInt(&o.MaxEjectionPercent, DefaultOutlierMaxEjectP)
		}
	}

	if b := c.Bans; b != nil {
		setInt(&b.MaxEntries, DefaultBanMaxEntries)
		setStr(&b.Action, "drop")
		for i := range b.Triggers {
			t := &b.Triggers[i]
			if t.Escalation == 0 {
				t.Escalation = DefaultBanEscalation
			}
			setDur(&t.MaxDuration, DefaultBanMaxDuration)
		}
	}
	if w := c.WAF; w != nil {
		setStr(&w.DefaultMode, "block")
		setStr(&w.DefaultProfile, "default")
		if w.RequestBodyLimit == 0 {
			w.RequestBodyLimit = DefaultWAFRequestBodyLimit
		}
		setStr(&w.RequestBodyLimitAction, "reject")
		if w.ResponseBodyLimit == 0 {
			w.ResponseBodyLimit = DefaultWAFResponseBodyLimit
		}
		if len(w.ResponseMIMETypes) == 0 {
			w.ResponseMIMETypes = []string{"text/plain", "text/html", "text/xml", "application/json", "application/xml"}
		}
		for i := range w.Profiles {
			if crs := w.Profiles[i].CRS; crs != nil {
				setInt(&crs.ParanoiaLevel, DefaultCRSParanoia)
				setInt(&crs.InboundThreshold, DefaultCRSInbound)
				setInt(&crs.OutboundThreshold, DefaultCRSOutbound)
			}
		}
	}

	if cl := c.Cluster; cl != nil {
		if cl.NodeID == "" {
			if h, err := os.Hostname(); err == nil {
				cl.NodeID = h
			} else {
				cl.NodeID = "xproxy"
			}
		}
		setDur(&cl.GossipInterval, time.Second)
		if cl.PeerStale == 0 {
			cl.PeerStale = cl.GossipInterval * 3
		}
		setInt(&cl.MaxKeysPerReport, 4096)
	}

	if sh := c.Shedding; sh != nil {
		setDur(&sh.TargetLatency, 250*time.Millisecond)
		setDur(&sh.Window, 10*time.Second)
		if sh.Low == 0 {
			sh.Low = 0.6
		}
		if sh.Normal == 0 {
			sh.Normal = 0.8
		}
		if sh.High == 0 {
			sh.High = 0.95
		}
		if sh.Hysteresis == 0 {
			sh.Hysteresis = 0.1
		}
		setDur(&sh.RetryAfter, 2*time.Second)
	}
	if j := c.JWT; j != nil {
		for i := range j.Providers {
			p := &j.Providers[i]
			if len(p.Algorithms) == 0 {
				p.Algorithms = []string{"RS256", "ES256", "EdDSA"}
			}
			setDur(&p.JWKSRefresh, time.Hour)
			setDur(&p.ClockSkew, 30*time.Second)
			setStr(&p.Source, "bearer")
		}
	}
	if ic := c.ICAP; ic != nil {
		for i := range ic.Services {
			s := &ic.Services[i]
			setDur(&s.ConnectTimeout, 2*time.Second)
			setDur(&s.Timeout, 5*time.Second)
			setInt(&s.MaxConns, 8)
			if s.MaxBody == 0 {
				s.MaxBody = 10 << 20
			}
			setStr(&s.BodyLimitAction, "reject")
			setStr(&s.Fail, "closed")
			setStr(&s.Preview, "auto")
		}
	}
	if a := c.ACME; a != nil {
		setStr(&a.StateDir, "/var/lib/xproxy/acme")
		setStr(&a.Challenge, "http-01")
		setDur(&a.RenewBefore, 30*24*time.Hour)
		setDur(&a.CheckInterval, 12*time.Hour)
	}
	for i := range c.Filters {
		setStr(&c.Filters[i].Stage, StageAfterAuth)
	}
	if cp := c.Compression; cp != nil {
		setInt(&cp.Level, 5)
		setInt(&cp.MinBytes, 1024)
		if len(cp.Types) == 0 {
			cp.Types = append([]string(nil), DefaultCompressionTypes...)
		}
	}
	if c.Cache != nil {
		if c.Cache.MaxBytes == 0 {
			c.Cache.MaxBytes = 64 << 20
		}
		if c.Cache.MaxObjectBytes == 0 {
			c.Cache.MaxObjectBytes = 1 << 20
		}
	}
	for i := range c.Routes {
		if rc := c.Routes[i].Cache; rc != nil {
			setDur(&rc.TTL, 60*time.Second)
			if len(rc.Methods) == 0 {
				rc.Methods = []string{"GET", "HEAD"}
			}
			if len(rc.Statuses) == 0 {
				rc.Statuses = []int{200, 203, 204, 300, 301, 404, 410}
			}
			setStr(&rc.Query, "all")
		}
		if g := c.Routes[i].Geo; g != nil {
			setStr(&g.Unknown, "allow")
			for j := range g.Allow {
				g.Allow[j] = strings.ToUpper(g.Allow[j])
			}
			for j := range g.Deny {
				g.Deny[j] = strings.ToUpper(g.Deny[j])
			}
		}
	}
	setDur(&c.Metrics.SampleInterval, 10*time.Second)
	setDur(&c.Metrics.Retention, time.Hour)
	if o := c.Metrics.OTLP; o != nil {
		setDur(&o.Interval, 30*time.Second)
		setDur(&o.Timeout, 10*time.Second)
		setStr(&o.ServiceName, "xproxy")
		if o.Compress == nil {
			t := true
			o.Compress = &t
		}
	}
	if ch := c.Challenge; ch != nil {
		setInt(&ch.Difficulty, 16)
		setDur(&ch.TTL, time.Hour)
		setStr(&ch.CookieName, "XPCHAL")
		setStr(&ch.Title, "Checking your browser")
	}

	for i := range c.Routes {
		r := &c.Routes[i]
		setStr(&r.PriorityClass, "normal")
		if r.Challenge != nil {
			setStr(&r.Challenge.Mode, "always")
			if r.Challenge.Level == 0 {
				r.Challenge.Level = 0.5
			}
		}
		if r.WAF != nil {
			if c.WAF != nil {
				setStr(&r.WAF.Mode, c.WAF.DefaultMode)
				setStr(&r.WAF.Profile, c.WAF.DefaultProfile)
			}
		}
		if len(r.Paths) == 0 && len(r.PathRegex) == 0 {
			r.Paths = []string{"/"}
		}
		if r.Redirect != nil && r.Redirect.Status == 0 {
			r.Redirect.Status = 308
		}
		if r.Respond != nil && r.Respond.Status == 0 {
			r.Respond.Status = 200
		}
		if m := r.Mirror; m != nil {
			setInt(&m.Percent, 100)
			if m.MaxBodyBytes == 0 {
				m.MaxBodyBytes = 1 << 20
			}
			setDur(&m.Timeout, 5*time.Second)
			setInt(&m.MaxInFlight, 64)
		}
		if hp := r.Honeypot; hp != nil {
			setInt(&hp.Status, 200)
			setStr(&hp.ContentType, "text/html; charset=utf-8")
			setDur(&hp.Mark, time.Hour)
			if hp.Decoy == "" && hp.Body == "" && hp.BodyFile == "" {
				hp.Decoy = "admin-login"
			}
		}
	}
}

func ingressDefaults(c *Config) {
	in := c.Ingress
	if in == nil {
		return
	}
	setStr(&in.APIServer, "https://kubernetes.default.svc")
	setStr(&in.TokenFile, "/var/run/secrets/kubernetes.io/serviceaccount/token")
	setStr(&in.CAFile, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	setStr(&in.Class, "xproxy")
	setStr(&in.CertDir, "/var/lib/xproxy/ingress")
	setDur(&in.Resync, 30*time.Second)
	setDur(&in.Timeout, 10*time.Second)
	setDur(&in.Debounce, 500*time.Millisecond)
}

func setInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setDur(p *Duration, v time.Duration) {
	if *p == 0 {
		*p = Duration(v)
	}
}

func setStr(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func tracingOTLP(t *Tracing) *OTLPExport {
	if t == nil {
		return nil
	}
	return t.OTLP
}
