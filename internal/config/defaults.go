package config

import "time"

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

	DefaultAffinityCookie = "XPSESS"
	DefaultAffinityTTL    = time.Hour

	DefaultOutlierFailures  = 5
	DefaultOutlierBaseTime  = 30 * time.Second
	DefaultOutlierMaxEjectP = 50

	DefaultTarpitDelay = 10 * time.Second

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
		for j := range u.Endpoints {
			setInt(&u.Endpoints[j].Weight, 1)
		}
		if hc := u.HealthCheck; hc != nil {
			setStr(&hc.Path, DefaultHealthCheckPath)
			setDur(&hc.Interval, DefaultHealthInterval)
			setDur(&hc.Timeout, DefaultHealthTimeout)
			setInt(&hc.HealthyThreshold, DefaultHealthyCount)
			setInt(&hc.UnhealthyThreshold, DefaultUnhealthyCount)
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

	for i := range c.Routes {
		r := &c.Routes[i]
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
