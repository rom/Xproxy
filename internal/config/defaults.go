package config

import (
	"os"
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

	for i := range s.Listeners {
		ln := &s.Listeners[i]
		if len(ln.Protocols) == 0 {
			if ln.TLS != nil {
				ln.Protocols = []Protocol{ProtocolH1, ProtocolH2}
			} else {
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
	setDur(&c.Metrics.SampleInterval, 10*time.Second)
	setDur(&c.Metrics.Retention, time.Hour)
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
		if len(r.Paths) == 0 {
			r.Paths = []string{"/"}
		}
		if r.Redirect != nil && r.Redirect.Status == 0 {
			r.Redirect.Status = 308
		}
		if r.Respond != nil && r.Respond.Status == 0 {
			r.Respond.Status = 200
		}
	}
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
