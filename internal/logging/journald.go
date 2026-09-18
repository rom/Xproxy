package logging

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// journaldSink speaks the native journald protocol: a datagram of
// KEY=VALUE lines, with a binary form (KEY newline, little endian length,
// data, newline) for values containing newlines. The JSON line becomes
// MESSAGE and top-level attributes become XPROXY_* fields so that
// journalctl can filter on them without parsing JSON.
type journaldSink struct {
	cfg  config.Journald
	mu   sync.Mutex
	conn *net.UnixConn
	drop dropCounter
}

const maxJournalDatagram = 60 << 10

func newJournaldSink(cfg config.Journald) *journaldSink {
	return &journaldSink{cfg: cfg}
}

func (j *journaldSink) dial() (*net.UnixConn, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.conn != nil {
		return j.conn, nil
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: j.cfg.Socket, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	j.conn = c
	return c, nil
}

func (j *journaldSink) reset() {
	j.mu.Lock()
	if j.conn != nil {
		_ = j.conn.Close()
		j.conn = nil
	}
	j.mu.Unlock()
}

func (j *journaldSink) emit(level slog.Level, stream string, line []byte, rec slog.Record) {
	var b bytes.Buffer
	writeField(&b, "MESSAGE", line)
	writeField(&b, "PRIORITY", []byte{byte('0' + syslogSeverity(level))})
	writeField(&b, "SYSLOG_IDENTIFIER", []byte(j.cfg.Identifier))
	writeField(&b, "XPROXY_STREAM", []byte(stream))
	rec.Attrs(func(a slog.Attr) bool {
		key := journalKey(a.Key)
		if key == "" || b.Len() > maxJournalDatagram-1024 {
			return true
		}
		v := a.Value.String()
		if len(v) > 1024 {
			v = v[:1024]
		}
		writeField(&b, "XPROXY_"+key, []byte(v))
		return true
	})
	if b.Len() > maxJournalDatagram {
		// Too large even for the binary form over a datagram; keep the
		// message and the fixed fields only.
		b.Reset()
		if len(line) > maxJournalDatagram-512 {
			line = line[:maxJournalDatagram-512]
		}
		writeField(&b, "MESSAGE", line)
		writeField(&b, "PRIORITY", []byte{byte('0' + syslogSeverity(level))})
		writeField(&b, "SYSLOG_IDENTIFIER", []byte(j.cfg.Identifier))
		writeField(&b, "XPROXY_STREAM", []byte(stream))
	}
	c, err := j.dial()
	if err != nil {
		j.drop.inc()
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := c.Write(b.Bytes()); err != nil {
		j.drop.inc()
		j.reset()
	}
}

func writeField(b *bytes.Buffer, key string, value []byte) {
	b.WriteString(key)
	if bytes.IndexByte(value, '\n') < 0 {
		b.WriteByte('=')
		b.Write(value)
		b.WriteByte('\n')
		return
	}
	b.WriteByte('\n')
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(value)))
	b.Write(l[:])
	b.Write(value)
	b.WriteByte('\n')
}

// journalKey turns an attribute name into a journal field name: upper
// case letters, digits and underscores, not starting with a digit or an
// underscore.
func journalKey(k string) string {
	var sb strings.Builder
	for i := 0; i < len(k) && sb.Len() < 60; i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z':
			sb.WriteByte(c - 32)
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			sb.WriteByte(c)
		default:
			sb.WriteByte('_')
		}
	}
	s := sb.String()
	if s == "" || s[0] == '_' || (s[0] >= '0' && s[0] <= '9') {
		return ""
	}
	return s
}

func (j *journaldSink) close() { j.reset() }
