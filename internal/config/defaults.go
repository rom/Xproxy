package config

import (
	"fmt"
	"github.com/rom/xproxy/internal/paths"
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
	DefaultMaxBufferedBody       = 512 << 20
	DefaultShutdownTimeout       = 30 * time.Second

	DefaultUpstreamConnect        = 5 * time.Second
	DefaultUpstreamResponseHeader = 30 * time.Second
	DefaultUpstreamIdle           = 90 * time.Second
	DefaultUpstreamTotal          = 5 * time.Minute
	DefaultMaxIdleConnsPerHost    = 64
	DefaultRetries                = 1
	// DefaultRetryBudgetPercent caps retries in flight at this share of
	// live requests; DefaultRetryBudgetMinConcurrency is the floor allowed
	// regardless. DefaultHedgeMax is the extra copies a hedge sends.
	DefaultRetryBudgetPercent        = 20
	DefaultRetryBudgetMinConcurrency = 3
	DefaultHedgeMax                  = 1

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
	// DefaultRateLimitNetV4 and NetV6 are the prefix lengths of the
	// client_net rate limit key.
	DefaultRateLimitNetV4 = 24
	DefaultRateLimitNetV6 = 48

	DefaultBanMaxEntries  = 100000
	DefaultBanEscalation  = 2.0
	DefaultBanMaxDuration = 24 * time.Hour

	DefaultWAFRequestBodyLimit  = 1 << 20
	DefaultWAFResponseBodyLimit = 512 << 10
	// DefaultWAFLearningMinHits is the matches before an exclusion is
	// proposed; DefaultWAFLearningMaxEntries bounds the learning table.
	// DefaultDiscoveryInterval is how often discovered endpoints are
	// re-resolved; DefaultDiscoveryTimeout bounds one resolution.
	DefaultDiscoveryInterval     = 30 * time.Second
	DefaultDiscoveryTimeout      = 5 * time.Second
	DefaultWAFLearningMinHits    = 5
	DefaultWAFLearningMaxEntries = 10000
	DefaultCRSParanoia           = 1
	// DefaultWAFAnomaly* tune behavioural anomaly detection: the window,
	// the requests a client needs before it is scored and the z-score at
	// which it is flagged; DefaultWAFAnomalyMaxClients bounds the tracker.
	DefaultWAFAnomalyWindow      = 5 * time.Minute
	DefaultWAFAnomalyMinRequests = 30
	DefaultWAFAnomalyThreshold   = 4.0
	DefaultWAFAnomalyMaxClients  = 65536
	DefaultCRSInbound            = 5
	DefaultCRSOutbound           = 4

	DefaultLogDirectory = paths.LogDir
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
	setInt64(&l.MaxBufferedBodyBytes, DefaultMaxBufferedBody)
	setStr(&c.Server.Normalization.Unicode, "off")

	for i := range s.Listeners {
		setStr(&s.Listeners[i].Kind, "http")
		if t := s.Listeners[i].TCP; t != nil {
			setDur(&t.IdleTimeout, 10*time.Minute)
			setInt(&t.MaxConnections, 10000)
			setDur(&t.QUICIdleTimeout, 30*time.Second)
			if t.YARA != nil {
				yaraDefaults(t.YARA)
			}
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
			if ic := f.Intercept; ic != nil {
				if ic.VerifyUpstream == nil {
					t := true
					ic.VerifyUpstream = &t
				}
				setStr(&ic.MinVersion, "1.2")
				setInt(&ic.MaxCache, 1024)
				setDur(&ic.LeafTTL, 24*time.Hour)
				if len(ic.ALPN) == 0 {
					ic.ALPN = []string{"http/1.1"}
				}
				if ic.YARA != nil {
					yaraDefaults(ic.YARA)
				}
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
			if d.DNSSEC != nil {
				setInt(&d.DNSSEC.MaxLookups, 48)
			}
			setInt(&d.Cache.MaxEntries, 10000)
			setDur(&d.Cache.MinTTL, 5*time.Second)
			setDur(&d.Cache.MaxTTL, time.Hour)
			if d.Cache.NegativeTTL == 0 {
				d.Cache.NegativeTTL = Duration(60 * time.Second)
			}
			setInt(&d.MaxInFlight, 1024)
			if td := d.TunnelDetection; td != nil {
				setDur(&td.Window, 5*time.Minute)
				setInt(&td.MinQueries, 50)
				setInt(&td.MinSignals, 2)
				setFloat(&td.Entropy, 3.6)
				setInt(&td.MinLabelLength, 12)
				// These five may be switched off with an explicit 0, so
				// only an absent key takes the default.
				if td.EntropyShare == nil {
					td.EntropyShare = ptr(0.5)
				}
				if td.TXTShare == nil {
					td.TXTShare = ptr(0.5)
				}
				if td.NXDOMAINShare == nil {
					td.NXDOMAINShare = ptr(0.5)
				}
				if td.DistinctSubdomains == nil {
					td.DistinctSubdomains = ptr(50)
				}
				if td.PayloadBytes == nil {
					td.PayloadBytes = ptr(int64(4096))
				}
				setStr(&td.Action, "log")
				setDur(&td.Cooldown, 10*time.Minute)
				setInt(&td.MaxTracked, 65536)
			}
			if d.RateLimit != nil {
				if d.RateLimit.QPS == 0 {
					d.RateLimit.QPS = 50
				}
				setInt(&d.RateLimit.Burst, 100)
			}
		}
		if m := s.Listeners[i].SMTP; m != nil {
			if m.TLSMode == "" {
				if s.Listeners[i].TLS != nil {
					m.TLSMode = "starttls"
				} else {
					m.TLSMode = "none"
				}
			}
			// require_tls defaults on where TLS is reachable at all.
			// A listener that offers STARTTLS and does not insist on it
			// is one downgrade away from sending the password in clear.
			if !m.RequireTLS && (m.TLSMode == "starttls" || m.TLSMode == "implicit") {
				m.RequireTLS = true
			}
			setStr(&m.UpstreamTLSMode, "none")
			if m.UpstreamTLS != nil {
				setStr(&m.UpstreamTLS.MinVersion, "1.2")
			}
			setStr(&m.BareNewlines, "reject")
			setInt(&m.MaxCommandLine, smtpMaxCommandLine)
			setInt(&m.MaxTextLine, smtpMaxTextLine)
			setInt(&m.MaxRecipients, 100)
			setInt(&m.MaxMessages, 100)
			setInt(&m.MaxErrors, 10)
			setInt(&m.MaxConnections, 1000)
			setDur(&m.ReadTimeout, 5*time.Minute)
			setDur(&m.SessionTimeout, 30*time.Minute)
			if len(m.Commands) == 0 {
				m.Commands = append([]string(nil), DefaultSMTPCommands...)
			}
		}
		if q := s.Listeners[i].MQTT; q != nil {
			if q.TLSMode == "" {
				if s.Listeners[i].TLS != nil {
					q.TLSMode = "implicit"
				} else {
					q.TLSMode = "none"
				}
			}
			setStr(&q.UpstreamTLSMode, "none")
			if q.UpstreamTLS != nil {
				setStr(&q.UpstreamTLS.MinVersion, "1.2")
			}
			setStr(&q.Action, "disconnect")
			for _, b := range []**bool{&q.AllowEmptyClientID, &q.AllowRetain, &q.AllowWildcardSubscribe} {
				if *b == nil {
					t := true
					*b = &t
				}
			}
			if len(q.Versions) == 0 {
				q.Versions = append([]string(nil), DefaultMQTTVersions...)
			}
			setInt(&q.MaxClientID, 128)
			setInt(&q.MaxPacketSize, 1<<20)
			setInt(&q.MaxTopicLength, 512)
			setInt(&q.MaxTopicLevels, 16)
			setInt(&q.MaxSubscriptions, 64)
			setInt(&q.MaxConnections, 10000)
			setDur(&q.ConnectTimeout, 30*time.Second)
			setDur(&q.IdleTimeout, 10*time.Minute)
		}
		if h := s.Listeners[i].SSH; h != nil {
			setStr(&h.ServerVersion, "SSH-2.0-xproxy")
			setInt(&h.MaxAuthTries, 3)
			setInt(&h.MaxSessions, 1000)
			setInt(&h.MaxChannels, 16)
			setDur(&h.HandshakeTimeout, 30*time.Second)
			setDur(&h.IdleTimeout, 30*time.Minute)
			if len(h.AllowChannels) == 0 {
				h.AllowChannels = append([]string(nil), DefaultSSHChannels...)
			}
			if len(h.AllowRequests) == 0 {
				h.AllowRequests = append([]string(nil), DefaultSSHRequests...)
			}
			if len(h.AllowSubsystems) == 0 {
				h.AllowSubsystems = append([]string(nil), DefaultSSHSubsystems...)
			}
			sftpDefaults(h.SFTP)
			sshRecordingDefaults(h.Recording)
			// A principal's own sftp section is the same section and
			// gets the same defaults; without this it would fail
			// validation on a packet size nobody wrote.
			for j := range h.Principals {
				if pp := h.Principals[j].Policy; pp != nil {
					sftpDefaults(pp.SFTP)
					sshRecordingDefaults(pp.Recording)
				}
			}
			if h.MFA != nil {
				mfaDefaults(h.MFA)
			}
			if len(h.AllowEnv) == 0 {
				h.AllowEnv = append([]string(nil), DefaultSSHEnv...)
			}
			if h.AllowFileTransferCommands == nil {
				// Refused by default exactly where there is an sftp
				// policy to bypass.
				allow := h.SFTP == nil
				h.AllowFileTransferCommands = &allow
			}
		}
		if f := s.Listeners[i].FTP; f != nil {
			if f.TLSMode == "" {
				if s.Listeners[i].TLS != nil {
					f.TLSMode = "starttls"
				} else {
					f.TLSMode = "none"
				}
			}
			// A control connection in clear carries the password, so
			// require_tls defaults on wherever TLS is reachable at all.
			if !f.RequireTLS && (f.TLSMode == "starttls" || f.TLSMode == "implicit") {
				f.RequireTLS = true
			}
			setStr(&f.UpstreamTLSMode, "none")
			if f.UpstreamTLS != nil {
				setStr(&f.UpstreamTLS.MinVersion, "1.2")
			}
			if len(f.Commands) == 0 {
				f.Commands = append([]string(nil), DefaultFTPCommands...)
			}
			setStr(&f.DataPorts, "0-0")
			setInt(&f.MaxCommandLine, 4096)
			setInt(&f.MaxErrors, 10)
			setInt(&f.MaxConnections, 1000)
			setDur(&f.DataTimeout, 30*time.Second)
			setDur(&f.IdleTimeout, 5*time.Minute)
			if f.YARA != nil {
				yaraDefaults(f.YARA)
				f.YARA.Directions = []string{"client"}
			}
		}
		if g := s.Listeners[i].Syslog; g != nil {
			if g.UDP == nil {
				t := true
				g.UDP = &t
			}
			if g.TLSMode == "" {
				if s.Listeners[i].TLS != nil {
					g.TLSMode = "implicit"
				} else {
					g.TLSMode = "none"
				}
			}
			setStr(&g.Framing, "auto")
			setStr(&g.UpstreamFraming, "octet_counting")
			setStr(&g.UpstreamTLSMode, "none")
			if g.UpstreamTLS != nil {
				setStr(&g.UpstreamTLS.MinVersion, "1.2")
			}
			setStr(&g.Hostname, "annotate")
			setInt(&g.MaxMessageBytes, 8192)
			setInt(&g.MaxSenders, 65536)
			setInt(&g.MaxConnections, 1000)
			setInt(&g.Queue, 4096)
			setDur(&g.IdleTimeout, 5*time.Minute)
			if g.RateLimit > 0 && g.RateBurst == 0 {
				g.RateBurst = g.RateLimit
			}
			for j := range g.Redact {
				setStr(&g.Redact[j].With, "[redacted]")
			}
		}
		ln := &s.Listeners[i]
		if ln.Kind == "tcp" || ln.Kind == "dns" || ln.Kind == "smtp" || ln.Kind == "mqtt" || ln.Kind == "ssh" || ln.Kind == "ftp" || ln.Kind == "syslog" {
			// No HTTP protocol defaults on a non-HTTP listener; a dns,
			// smtp or mqtt listener with TLS still gets the TLS
			// defaults.
			if (ln.Kind == "dns" || ln.Kind == "smtp" || ln.Kind == "mqtt" || ln.Kind == "ftp" || ln.Kind == "syslog") && ln.TLS != nil {
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
	if s := lg.SIEM; s != nil {
		setStr(&s.Format, "json")
		setDur(&s.Timeout, 10*time.Second)
		setInt(&s.Batch, 512)
		setDur(&s.Interval, 5*time.Second)
		setInt(&s.Queue, 8192)
		setStr(&s.Vendor, "Sysctl")
		setStr(&s.Product, "Xproxy")
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
		setStr(&rl.Algorithm, "token_bucket")
		setStr(&rl.Distributed, "approximate")
		setInt(&rl.NetV4, DefaultRateLimitNetV4)
		setInt(&rl.NetV6, DefaultRateLimitNetV6)
		if rl.Algorithm == "sliding_window" {
			setDur(&rl.Window, time.Second)
		} else if rl.Burst == 0 && rl.Rate > 0 {
			rl.Burst = int(rl.Rate)
			if rl.Burst < 1 {
				rl.Burst = 1
			}
		}
		setDur(&rl.TarpitDelay, DefaultTarpitDelay)
	}

	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if os := u.OriginSignature; os != nil {
			setStr(&os.Header, "X-Xproxy-Signature")
			setDur(&os.TTL, 5*time.Minute)
		}
		setStr(&u.Balancer, "round_robin")
		setStr(&u.Scheme, "http")
		setDur(&u.Timeouts.Connect, DefaultUpstreamConnect)
		setDur(&u.Timeouts.ResponseHeader, DefaultUpstreamResponseHeader)
		setDur(&u.Timeouts.Idle, DefaultUpstreamIdle)
		setDur(&u.Timeouts.Total, DefaultUpstreamTotal)
		setInt(&u.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
		if d := u.Discovery; d != nil {
			setStr(&d.Type, "dns")
			if d.Type == "http" {
				setStr(&d.Format, "list")
			}
			setDur(&d.Interval, DefaultDiscoveryInterval)
			setDur(&d.Timeout, DefaultDiscoveryTimeout)
			setInt(&d.Weight, 1)
		}
		if u.Retries == nil {
			r := DefaultRetries
			u.Retries = &r
		}
		if b := u.RetryBudget; b != nil {
			if b.Percent == 0 {
				b.Percent = DefaultRetryBudgetPercent
			}
			if b.MinConcurrency == 0 {
				b.MinConcurrency = DefaultRetryBudgetMinConcurrency
			}
		}
		if h := u.Hedge; h != nil {
			setInt(&h.Max, DefaultHedgeMax)
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
		if u.H3 && u.H3Fallback == nil {
			t := true
			u.H3Fallback = &t
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
			setInt(&o.LatencyMinSamples, DefaultOutlierLatencySamples)
		}
	}

	if b := c.Bans; b != nil {
		setInt(&b.MaxEntries, DefaultBanMaxEntries)
		setStr(&b.Action, "drop")
		for i := range b.Triggers {
			t := &b.Triggers[i]
			setStr(&t.Aggregate, "address")
			setInt(&t.NetV4, 24)
			setInt(&t.NetV6, 48)
			setInt(&t.MinSources, 1)
			if t.Escalation == 0 {
				t.Escalation = DefaultBanEscalation
			}
			setDur(&t.MaxDuration, DefaultBanMaxDuration)
		}
	}
	errorPageDefaults(c.Server.ErrorPages)
	if st := c.Server.SessionTickets; st != nil {
		setDur(&st.Rotate, DefaultTicketRotate)
	}
	for i := range c.Routes {
		errorPageDefaults(c.Routes[i].ErrorPages)
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
		if l := w.Learning; l != nil {
			setInt(&l.MinHits, DefaultWAFLearningMinHits)
			setInt(&l.MaxEntries, DefaultWAFLearningMaxEntries)
		}
		if a := w.Anomaly; a != nil {
			setDur(&a.Window, DefaultWAFAnomalyWindow)
			setInt(&a.MinRequests, DefaultWAFAnomalyMinRequests)
			if a.Threshold == 0 {
				a.Threshold = DefaultWAFAnomalyThreshold
			}
			setStr(&a.Action, "log")
			setInt(&a.MaxClients, DefaultWAFAnomalyMaxClients)
		}
		for i := range w.Profiles {
			if crs := w.Profiles[i].CRS; crs != nil {
				setInt(&crs.ParanoiaLevel, DefaultCRSParanoia)
				setInt(&crs.InboundThreshold, DefaultCRSInbound)
				setInt(&crs.OutboundThreshold, DefaultCRSOutbound)
			}
			for j := range w.Profiles[i].JSONSchemas {
				js := &w.Profiles[i].JSONSchemas[j]
				if len(js.Methods) == 0 {
					js.Methods = []string{"POST", "PUT", "PATCH"}
				}
			}
		}
	}

	for i := range c.VirtualPatches {
		p := &c.VirtualPatches[i]
		setStr(&p.Action, "block")
		setInt(&p.Status, 403)
		if p.Body != nil && p.Body.MaxBytes == 0 {
			p.Body.MaxBytes = 64 << 10
		}
	}
	for i := range c.SecurityTxt {
		st := &c.SecurityTxt[i]
		setStr(&st.Name, fmt.Sprintf("security_txt[%d]", i))
		setDur(&st.CacheFor, time.Hour)
		if st.Expires == "" {
			// A year is the longest RFC 9116 recommends, and a reload
			// pushes it forward, so the document cannot quietly expire.
			setDur(&st.ValidFor, 365*24*time.Hour)
		}
	}
	for i := range c.Routes {
		if pol := c.Routes[i].Policy; pol != nil {
			for j := range pol.Query {
				setStr(&pol.Query[j].Type, "string")
				setInt(&pol.Query[j].MaxRepeat, 1)
			}
		}
	}
	if a := c.APIInventory; a != nil {
		setInt(&a.MaxEndpoints, 10000)
		setDur(&a.ZombieAfter, 720*time.Hour)
		setDur(&a.SaveInterval, 5*time.Minute)
	}
	if d := c.Degradation; d != nil {
		for i := range d.Levels {
			if d.Levels[i].Name == "" {
				d.Levels[i].Name = fmt.Sprintf("levels[%d]", i)
			}
		}
	}
	for i := range c.Honeytokens {
		h := &c.Honeytokens[i]
		if h.Name == "" {
			h.Name = fmt.Sprintf("honeytokens[%d]", i)
		}
		setStr(&h.Match, "exact")
		setStr(&h.Action, "block")
		setInt(&h.Status, 403)
		if h.Mark == nil {
			d := Duration(24 * time.Hour)
			h.Mark = &d
		}
		if len(h.In) == 0 {
			h.In = []string{"headers", "cookies", "query", "path"}
		}
	}
	if cp := c.Capture; cp != nil {
		setStr(&cp.FilePrefix, "xproxy")
		setDur(&cp.MaxDuration, time.Hour)
		if cp.MaxFileBytes == 0 {
			cp.MaxFileBytes = 64 << 20
		}
		setInt(&cp.MaxFiles, 4)
		setInt(&cp.SnapLen, 256<<10)
		setInt(&cp.MaxBodyBytes, 64<<10)
		if cp.Redact == nil {
			// The values that should never be on disk in the clear, and
			// the ones an operator forgets. An explicit empty list turns
			// redaction off, which is a deliberate act.
			cp.Redact = []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "Api-Key"}
		}
		for i := range cp.Rules {
			setInt(&cp.Rules[i].Percent, 100)
			if cp.Rules[i].Name == "" {
				cp.Rules[i].Name = fmt.Sprintf("rules[%d]", i)
			}
		}
	}
	if f := c.Fleet; f != nil {
		setDur(&f.Interval, 30*time.Second)
		setDur(&f.Timeout, 10*time.Second)
		if f.NodeID == "" {
			if c.Cluster != nil && c.Cluster.NodeID != "" {
				f.NodeID = c.Cluster.NodeID
			} else if h, err := os.Hostname(); err == nil {
				f.NodeID = h
			} else {
				f.NodeID = "xproxy"
			}
		}
	}
	if cl := c.Cluster; cl != nil {
		setDur(&cl.ExactTimeout, DefaultExactTimeout)
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
			if in := p.Introspection; in != nil {
				setDur(&in.CacheTTL, DefaultIntrospectionCacheTTL)
				setDur(&in.Timeout, DefaultIntrospectionTimeout)
			}
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
		setStr(&a.StateDir, paths.StateDir+"/acme")
		setStr(&a.Challenge, "http-01")
		setDur(&a.RenewBefore, 30*24*time.Hour)
		setDur(&a.CheckInterval, 12*time.Hour)
	}
	for i := range c.Filters {
		setStr(&c.Filters[i].Stage, StageAfterAuth)
	}
	if cp := c.Compression; cp != nil {
		if len(cp.Encodings) == 0 {
			cp.Encodings = []string{"br", "zstd", "gzip"}
		}
		if cp.BrotliLevel == nil {
			l := DefaultBrotliLevel
			cp.BrotliLevel = &l
		}
		setInt(&cp.ZstdLevel, DefaultZstdLevel)
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
	if m := c.Maintenance; m != nil {
		setInt(&m.Status, 503)
		setDur(&m.RetryAfter, 300*time.Second)
		setStr(&m.Message, "The service is temporarily unavailable for maintenance.")
	}
	if ch := c.Challenge; ch != nil {
		setInt(&ch.Difficulty, 16)
		setDur(&ch.TTL, time.Hour)
		setStr(&ch.CookieName, "XPCHAL")
		setStr(&ch.Title, "Checking your browser")
		if cp := ch.Captcha; cp != nil {
			setDur(&cp.Timeout, 5*time.Second)
			setStr(&cp.Mode, "escalation")
		}
	}

	for i := range c.Routes {
		r := &c.Routes[i]
		setStr(&r.PriorityClass, "normal")
		if r.CORS != nil {
			if len(r.CORS.AllowMethods) == 0 {
				r.CORS.AllowMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
			}
			setDur(&r.CORS.MaxAge, 10*time.Minute)
		}
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
			if d := m.Diff; d != nil {
				setInt(&d.SamplePercent, 100)
				if d.MaxBodyBytes == 0 {
					d.MaxBodyBytes = 64 << 10
				}
			}
		}
		if d := r.Deceive; d != nil {
			setInt(&d.Status, 200)
			if d.Decoy == "" && d.Body == "" && d.BodyFile == "" {
				d.Body = "{}"
				setStr(&d.ContentType, "application/json")
			}
			setStr(&d.ContentType, "text/html; charset=utf-8")
		}
		if hp := r.Honeypot; hp != nil {
			setInt(&hp.Status, 200)
			setStr(&hp.ContentType, "text/html; charset=utf-8")
			if hp.Mark == nil {
				// Absent means the usual hour; an explicit 0 means this
				// honeypot marks nobody.
				d := Duration(time.Hour)
				hp.Mark = &d
			}
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
	setStr(&in.CertDir, paths.StateDir+"/ingress")
	setDur(&in.Resync, 30*time.Second)
	setDur(&in.Timeout, 10*time.Second)
	setDur(&in.Debounce, 500*time.Millisecond)
}

func setInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setInt64(p *int64, v int64) {
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

// setFloat fills an unset fraction or threshold. Zero means unset here
// as everywhere else; a signal an operator wants switched off is
// switched off by its own share reaching zero through validation, not
// by leaving the key out.
func setFloat(p *float64, v float64) {
	if *p == 0 {
		*p = v
	}
}

// ptr is the default for a setting whose zero value an operator may
// mean: the pointer says whether the key was written at all.
func ptr[T any](v T) *T { return &v }

func tracingOTLP(t *Tracing) *OTLPExport {
	if t == nil {
		return nil
	}
	return t.OTLP
}

// errorPageDefaults fills an error pages section.
func errorPageDefaults(e *ErrorPages) {
	if e == nil {
		return
	}
	setStr(&e.ContentType, "text/html; charset=utf-8")
	if e.JSON == nil {
		t := true
		e.JSON = &t
	}
}

// Compression encoder defaults: Brotli 4 and zstd 2 balance ratio and CPU
// for dynamic responses.
const (
	DefaultBrotliLevel = 4
	DefaultZstdLevel   = 2
)

// DefaultTicketRotate is the session ticket key epoch.
const DefaultTicketRotate = 24 * time.Hour

// DefaultOutlierLatencySamples is the number of responses before an
// endpoint's latency can eject it.
const DefaultOutlierLatencySamples = 20

// DefaultExactTimeout bounds the wait for a key owner in exact
// distributed rate limiting.
const DefaultExactTimeout = 50 * time.Millisecond

// Defaults of OAuth 2.0 token introspection.
const (
	DefaultIntrospectionCacheTTL = time.Minute
	DefaultIntrospectionTimeout  = 3 * time.Second
)

// mfaDefaults fills an MFA policy wherever it is used.
func mfaDefaults(m *MFAPolicy) {
	setStr(&m.Issuer, "xproxy")
	setStr(&m.Prompt, "One-time code: ")
	if m.Skew == 0 {
		m.Skew = 1
	}
	if m.RequireEnrolment == nil {
		t := true
		m.RequireEnrolment = &t
	}
	setInt(&m.MaxFailures, 5)
	setDur(&m.Window, 5*time.Minute)
	setDur(&m.Duration, 15*time.Minute)
	setInt(&m.MaxUsers, 10000)
}

// yaraDefaults fills a YARA policy wherever it is used.
// sshRecordingDefaults fills one recording section, the listener's or a
// principal's.
func sshRecordingDefaults(r *SSHRecording) {
	if r == nil {
		return
	}
	for _, b := range []**bool{&r.Enabled, &r.Commands} {
		if *b == nil {
			t := true
			*b = &t
		}
	}
	setStr(&r.FilePrefix, "session")
	setInt(&r.MaxFiles, 1000)
	if r.MaxFileBytes == 0 {
		r.MaxFileBytes = 32 << 20
	}
}

// sftpDefaults fills one sftp section, the listener's or a
// principal's.
func sftpDefaults(p *SFTPPolicy) {
	if p == nil {
		return
	}
	setInt(&p.MaxPacketSize, 256<<10)
	setInt(&p.MaxOpenFiles, 256)
	if p.YARA != nil {
		yaraDefaults(p.YARA)
		// Only what the client writes is a file this listener is
		// choosing to accept; the other direction is a download, which
		// the path and operation policy already decides.
		p.YARA.Directions = []string{"client"}
	}
}

func yaraDefaults(y *YARAPolicy) {
	setStr(&y.Action, "close")
	setInt(&y.MaxWindow, 256<<10)
	if y.MaxBytes == 0 {
		y.MaxBytes = 32 << 20
	}
	if len(y.Directions) == 0 {
		y.Directions = []string{"client", "upstream"}
	}
}
