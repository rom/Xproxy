package logging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// syslogSink formats records as RFC 5424 or RFC 3164 messages and sends
// them over UDP, TCP, TCP with TLS, or a Unix datagram socket. Sending is
// asynchronous behind a bounded queue: the request path never waits for a
// collector, and a full queue drops with a counter. Stream connections are
// re-established with back-off.
type syslogSink struct {
	cfg      config.Syslog
	facility int
	hostname string
	pid      string
	queue    chan []byte
	drop     dropCounter
	sent     dropCounter
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	tlsCfg   *tls.Config
	meta     siemMeta
}

const maxSyslogDatagram = 8192

func newSyslogSink(cfg config.Syslog) (*syslogSink, error) {
	s := &syslogSink{
		cfg:      cfg,
		facility: config.SyslogFacility(cfg.Facility),
		hostname: cfg.Hostname,
		pid:      strconv.Itoa(os.Getpid()),
		queue:    make(chan []byte, cfg.QueueSize),
		stop:     make(chan struct{}),
	}
	if s.hostname == "" {
		if h, err := os.Hostname(); err == nil {
			s.hostname = h
		} else {
			s.hostname = "-"
		}
	}
	s.meta = siemMeta{vendor: "Sysctl", product: "Xproxy", version: Version, hostname: s.hostname}
	if cfg.Network == "tcp+tls" {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // validated configuration path
			if err != nil {
				return nil, fmt.Errorf("syslog ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("syslog ca file contains no certificates")
			}
			tc.RootCAs = pool
		}
		if cfg.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("syslog client certificate: %w", err)
			}
			tc.Certificates = []tls.Certificate{cert}
		}
		s.tlsCfg = tc
	}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

func (s *syslogSink) emit(level slog.Level, stream string, line []byte, rec slog.Record) {
	pri := s.facility*8 + syslogSeverity(level)
	var msg []byte
	format := s.cfg.Format
	switch format {
	case "cef":
		line = cefLine(s.meta, stream, level, rec)
	case "leef":
		line = leefLine(s.meta, stream, level, rec)
	}
	if format == "cef" || format == "leef" {
		format = "rfc5424"
		if s.cfg.Network == "unix" {
			format = "rfc3164"
		}
	}
	if format == "rfc3164" {
		// <PRI>Mmm dd hh:mm:ss host app[pid]: msg
		ts := rec.Time.Format(time.Stamp)
		msg = fmt.Appendf(nil, "<%d>%s %s %s[%s]: %s", pri, ts, s.hostname, s.cfg.AppName, s.pid, line)
	} else {
		// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
		ts := rec.Time.UTC().Format(time.RFC3339Nano)
		msgid := stream
		if msgid == "" {
			msgid = "-"
		}
		msg = fmt.Appendf(nil, "<%d>1 %s %s %s %s %s - %s", pri, ts, s.hostname, s.cfg.AppName, s.pid, msgid, line)
	}
	if (s.cfg.Network == "udp" || s.cfg.Network == "unix") && len(msg) > maxSyslogDatagram {
		msg = msg[:maxSyslogDatagram]
	}
	select {
	case s.queue <- msg:
	default:
		s.drop.inc()
	}
}

func (s *syslogSink) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := &net.Dialer{Timeout: 5 * time.Second}
	switch s.cfg.Network {
	case "unix":
		return d.DialContext(ctx, "unixgram", s.cfg.Address)
	case "udp":
		return d.DialContext(ctx, "udp", s.cfg.Address)
	case "tcp":
		return d.DialContext(ctx, "tcp", s.cfg.Address)
	case "tcp+tls":
		td := &tls.Dialer{NetDialer: d, Config: s.tlsCfg}
		return td.DialContext(ctx, "tcp", s.cfg.Address)
	}
	return nil, fmt.Errorf("unsupported syslog network %q", s.cfg.Network)
}

func (s *syslogSink) loop() {
	defer s.wg.Done()
	var conn net.Conn
	backoff := time.Second
	stream := s.cfg.Network == "tcp" || s.cfg.Network == "tcp+tls"
	for {
		var msg []byte
		select {
		case <-s.stop:
			if conn != nil {
				_ = conn.Close()
			}
			return
		case msg = <-s.queue:
		}
		for attempt := 0; attempt < 2; attempt++ {
			if conn == nil {
				c, err := s.dial()
				if err != nil {
					select {
					case <-time.After(backoff):
					case <-s.stop:
						return
					}
					backoff = min(backoff*2, 30*time.Second)
					continue
				}
				conn = c
				backoff = time.Second
			}
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			var err error
			if stream {
				// RFC 6587 octet counting framing.
				_, err = conn.Write(append([]byte(strconv.Itoa(len(msg))+" "), msg...))
			} else {
				_, err = conn.Write(msg)
			}
			if err == nil {
				s.sent.inc()
				break
			}
			_ = conn.Close()
			conn = nil
			if attempt == 1 {
				s.drop.inc()
			}
		}
	}
}

func (s *syslogSink) close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
}
