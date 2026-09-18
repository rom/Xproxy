package tlsconf

import (
	"crypto/md5" //nolint:gosec // JA3 is defined over MD5; not used for security
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Fingerprint is what the ClientHello says about the client software,
// in the two common notations: JA3 (MD5 of the raw lists) and JA4 (the
// structured, sortable form). Both ignore GREASE values.
type Fingerprint struct {
	JA3 string // 32 hex characters
	JA4 string // t13d1516h2_8daaf6152771_b0da82dd1658
	// Summary fields for heuristics.
	ALPN     []string
	Ciphers  int
	SNI      bool
	Version  uint16
	ExtCount int
}

// isGREASE reports the reserved values clients randomly insert.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// Compute derives the fingerprint from a ClientHello. quic reports true
// for a QUIC handshake (JA4 prefix "q").
func Compute(h *tls.ClientHelloInfo, quic bool) Fingerprint {
	var fp Fingerprint
	fp.SNI = h.ServerName != ""
	fp.ALPN = h.SupportedProtos
	var version uint16
	for _, v := range h.SupportedVersions {
		if !isGREASE(v) && v > version {
			version = v
		}
	}
	fp.Version = version

	// JA3: version,ciphers,extensions,curves,points (decimal, '-' joined).
	join := func(vals []uint16) string {
		parts := make([]string, 0, len(vals))
		for _, v := range vals {
			if !isGREASE(v) {
				parts = append(parts, strconv.Itoa(int(v)))
			}
		}
		return strings.Join(parts, "-")
	}
	ciphers := make([]uint16, 0, len(h.CipherSuites))
	for _, c := range h.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	fp.Ciphers = len(ciphers)
	curves := make([]uint16, 0, len(h.SupportedCurves))
	for _, c := range h.SupportedCurves {
		if !isGREASE(uint16(c)) { //nolint:gosec // CurveID is 16 bit
			curves = append(curves, uint16(c)) //nolint:gosec // CurveID is 16 bit
		}
	}
	points := make([]uint16, 0, len(h.SupportedPoints))
	for _, p := range h.SupportedPoints {
		points = append(points, uint16(p))
	}
	exts := make([]uint16, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		if !isGREASE(e) {
			exts = append(exts, e)
		}
	}
	fp.ExtCount = len(exts)
	// The ClientHello legacy version field is 0x0303 for every TLS 1.2+
	// hello; Go does not expose it, so JA3 uses that value.
	legacy := uint16(0x0303)
	if version != 0 && version < 0x0303 {
		legacy = version
	}
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", legacy, join(ciphers), join(exts), join(curves), join(points))
	sum := md5.Sum([]byte(ja3)) //nolint:gosec // JA3 definition
	fp.JA3 = hex.EncodeToString(sum[:])

	// JA4: q/t + version + d/i + cipher count + extension count + ALPN
	// first and last character + '_' + sha256(sorted ciphers)[:12] + '_' +
	// sha256(sorted extensions without SNI and ALPN + '_' + sigalgs)[:12].
	proto := "t"
	if quic {
		proto = "q"
	}
	ver := "00"
	switch version {
	case tls.VersionTLS13:
		ver = "13"
	case tls.VersionTLS12:
		ver = "12"
	case tls.VersionTLS11:
		ver = "11"
	case tls.VersionTLS10:
		ver = "10"
	}
	sni := "i"
	if fp.SNI {
		sni = "d"
	}
	alpn := "00"
	if len(h.SupportedProtos) > 0 && h.SupportedProtos[0] != "" {
		a := h.SupportedProtos[0]
		alpn = string(a[0]) + string(a[len(a)-1])
	}
	sortedHex := func(vals []uint16) string {
		s := append([]uint16{}, vals...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		parts := make([]string, len(s))
		for i, v := range s {
			parts[i] = fmt.Sprintf("%04x", v)
		}
		return strings.Join(parts, ",")
	}
	ja4Exts := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 { // SNI and ALPN are counted, not hashed
			ja4Exts = append(ja4Exts, e)
		}
	}
	sigs := make([]string, 0, len(h.SignatureSchemes))
	for _, s := range h.SignatureSchemes {
		if !isGREASE(uint16(s)) { //nolint:gosec // SignatureScheme is 16 bit
			sigs = append(sigs, fmt.Sprintf("%04x", uint16(s))) //nolint:gosec // SignatureScheme is 16 bit
		}
	}
	extPart := sortedHex(ja4Exts)
	if len(sigs) > 0 {
		extPart += "_" + strings.Join(sigs, ",")
	}
	hash12 := func(s string) string {
		if s == "" {
			return "000000000000"
		}
		d := sha256.Sum256([]byte(s))
		return hex.EncodeToString(d[:])[:12]
	}
	fp.JA4 = fmt.Sprintf("%s%s%s%02d%02d%s_%s_%s", proto, ver, sni, min(len(ciphers), 99), min(len(exts), 99), alpn, hash12(sortedHex(ciphers)), hash12(extPart))
	return fp
}

// FingerprintTable remembers the fingerprint of open connections by
// remote address so the request handler can look it up. It is bounded;
// entries are removed when the connection closes and evicted in FIFO
// order under pressure.
type FingerprintTable struct {
	mu    sync.Mutex
	by    map[string]Fingerprint
	order []string
	max   int
}

// NewFingerprintTable creates a table bounded to max entries.
func NewFingerprintTable(max int) *FingerprintTable {
	return &FingerprintTable{by: make(map[string]Fingerprint, 1024), max: max}
}

// Put records the fingerprint of a connection.
func (t *FingerprintTable) Put(remote string, fp Fingerprint) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.by[remote]; !ok {
		if len(t.by) >= t.max && len(t.order) > 0 {
			delete(t.by, t.order[0])
			t.order = t.order[1:]
		}
		t.order = append(t.order, remote)
	}
	t.by[remote] = fp
}

// Get returns the fingerprint of a connection.
func (t *FingerprintTable) Get(remote string) (Fingerprint, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fp, ok := t.by[remote]
	return fp, ok
}

// Delete forgets a closed connection.
func (t *FingerprintTable) Delete(remote string) {
	t.mu.Lock()
	delete(t.by, remote)
	t.mu.Unlock()
}

// Len returns the number of tracked connections.
func (t *FingerprintTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.by)
}
