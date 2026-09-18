package tlsconf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Certificate Transparency (RFC 6962): the signed certificate timestamps
// a CA embeds in a certificate prove that it was logged. The proxy checks
// them at load so that a certificate issued without logging (which
// browsers reject) never reaches a listener unnoticed, and verifies the
// signatures when a log list with the logs' keys is configured.

// sctExtensionOID is the X.509 extension carrying embedded SCTs.
var sctExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SCT is one parsed signed certificate timestamp.
type SCT struct {
	LogID     string    `json:"log_id"` // base64
	Timestamp time.Time `json:"timestamp"`
	Verified  bool      `json:"verified"`
	Error     string    `json:"error,omitempty"`
	raw       sctRaw
}

type sctRaw struct {
	version   byte
	logID     [32]byte
	timestamp uint64
	exts      []byte
	hashAlg   byte
	sigAlg    byte
	sig       []byte
}

// CTStatus summarises a certificate's SCTs for the management API.
type CTStatus struct {
	Embedded int    `json:"embedded"`
	Verified int    `json:"verified"`
	Required int    `json:"required"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	SCTs     []SCT  `json:"scts,omitempty"`
}

// ParseSCTs extracts the embedded SCTs of a certificate. A certificate
// without the extension yields an empty list and no error.
func ParseSCTs(leaf *x509.Certificate) ([]SCT, error) {
	var payload []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(sctExtensionOID) {
			payload = ext.Value
		}
	}
	if payload == nil {
		return nil, nil
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(payload, &octets); err != nil || len(rest) != 0 {
		return nil, errors.New("sct extension is not an OCTET STRING")
	}
	s := cryptobyte.String(octets)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
		return nil, errors.New("sct list framing")
	}
	var out []SCT
	for !list.Empty() {
		var one cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&one) {
			return nil, errors.New("sct framing")
		}
		sct, err := parseSCT(one)
		if err != nil {
			return nil, err
		}
		out = append(out, sct)
		if len(out) > 32 {
			return nil, errors.New("more than 32 scts")
		}
	}
	return out, nil
}

func parseSCT(s cryptobyte.String) (SCT, error) {
	var r sctRaw
	var ts uint64
	var exts cryptobyte.String
	var sig cryptobyte.String
	if !s.ReadUint8(&r.version) || !s.CopyBytes(r.logID[:]) || !s.ReadUint64(&ts) ||
		!s.ReadUint16LengthPrefixed(&exts) || !s.ReadUint8(&r.hashAlg) || !s.ReadUint8(&r.sigAlg) ||
		!s.ReadUint16LengthPrefixed(&sig) || !s.Empty() {
		return SCT{}, errors.New("malformed sct")
	}
	if r.version != 0 {
		return SCT{}, fmt.Errorf("sct version %d not supported", r.version)
	}
	r.timestamp = ts
	r.exts = []byte(exts)
	r.sig = []byte(sig)
	return SCT{LogID: base64.StdEncoding.EncodeToString(r.logID[:]), Timestamp: time.UnixMilli(int64(ts)).UTC(), raw: r}, nil //nolint:gosec // millisecond timestamps fit
}

// LogList maps log ids to public keys, read from a log list file in the
// format Google publishes (v3: operators[].logs[] and tiled_logs[] with
// log_id and key as base64).
type LogList struct {
	keys map[[32]byte]crypto.PublicKey
	Logs int
}

// LoadLogList reads a log list file.
func LoadLogList(path string) (*LogList, error) {
	data, err := os.ReadFile(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	return ParseLogList(data)
}

// ParseLogList parses log list JSON.
func ParseLogList(data []byte) (*LogList, error) {
	var doc struct {
		Operators []struct {
			Logs []struct {
				LogID string `json:"log_id"`
				Key   string `json:"key"`
			} `json:"logs"`
			TiledLogs []struct {
				LogID string `json:"log_id"`
				Key   string `json:"key"`
			} `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("log list: %w", err)
	}
	ll := &LogList{keys: map[[32]byte]crypto.PublicKey{}}
	add := func(id, key string) error {
		rawID, err := base64.StdEncoding.DecodeString(id)
		if err != nil || len(rawID) != 32 {
			return fmt.Errorf("log list: bad log_id %q", id)
		}
		der, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("log list: bad key for %s", id)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return fmt.Errorf("log list: key for %s: %w", id, err)
		}
		var k [32]byte
		copy(k[:], rawID)
		ll.keys[k] = pub
		ll.Logs++
		return nil
	}
	for _, op := range doc.Operators {
		for _, l := range op.Logs {
			if err := add(l.LogID, l.Key); err != nil {
				return nil, err
			}
		}
		for _, l := range op.TiledLogs {
			if err := add(l.LogID, l.Key); err != nil {
				return nil, err
			}
		}
	}
	if ll.Logs == 0 {
		return nil, errors.New("log list: no logs")
	}
	return ll, nil
}

// Key returns the public key of a log.
func (l *LogList) Key(id [32]byte) (crypto.PublicKey, bool) {
	if l == nil {
		return nil, false
	}
	k, ok := l.keys[id]
	return k, ok
}

// VerifySCTs checks the embedded SCTs of leaf against the log list: each
// SCT's signature over the precertificate entry (the TBSCertificate with
// the SCT extension removed, and the issuer's key hash) must verify with
// the log's key. Without an issuer the signatures cannot be checked and
// only presence counts. The returned list carries the verdict per SCT.
func VerifySCTs(leaf, issuer *x509.Certificate, logs *LogList) ([]SCT, error) {
	scts, err := ParseSCTs(leaf)
	if err != nil || len(scts) == 0 || logs == nil {
		return scts, err
	}
	if issuer == nil {
		for i := range scts {
			scts[i].Error = "issuer certificate not available"
		}
		return scts, nil
	}
	tbs, err := precertTBS(leaf)
	if err != nil {
		return scts, err
	}
	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	for i := range scts {
		sct := &scts[i]
		key, ok := logs.Key(sct.raw.logID)
		if !ok {
			sct.Error = "log not in the list"
			continue
		}
		if err := verifySCTSignature(sct.raw, tbs, issuerKeyHash, key); err != nil {
			sct.Error = err.Error()
			continue
		}
		sct.Verified = true
	}
	return scts, nil
}

// verifySCTSignature checks one SCT over a precert entry.
func verifySCTSignature(r sctRaw, tbs []byte, issuerKeyHash [32]byte, key crypto.PublicKey) error {
	if r.hashAlg != 4 { // sha256
		return fmt.Errorf("hash algorithm %d not supported", r.hashAlg)
	}
	// digitally-signed struct: version, signature_type(certificate_timestamp),
	// timestamp, entry_type(precert_entry), signed_entry, extensions.
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(r.version)
	b.AddUint8(0)
	b.AddUint64(r.timestamp)
	b.AddUint16(1)
	b.AddBytes(issuerKeyHash[:])
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(r.exts) })
	signed, err := b.Bytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(signed)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if r.sigAlg != 3 {
			return errors.New("signature algorithm does not match the log key")
		}
		if !ecdsa.VerifyASN1(k, sum[:], r.sig) {
			return errors.New("signature does not verify")
		}
	case *rsa.PublicKey:
		if r.sigAlg != 1 {
			return errors.New("signature algorithm does not match the log key")
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], r.sig); err != nil {
			return errors.New("signature does not verify")
		}
	default:
		return errors.New("log key type not supported")
	}
	return nil
}

// precertTBS rebuilds the TBSCertificate with the SCT extension removed,
// which is what the log signed (RFC 6962, section 3.2).
func precertTBS(leaf *x509.Certificate) ([]byte, error) {
	in := cryptobyte.String(leaf.RawTBSCertificate)
	var tbs cryptobyte.String
	if !in.ReadASN1(&tbs, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errors.New("tbs: not a sequence")
	}
	out := cryptobyte.NewBuilder(nil)
	out.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		for !tbs.Empty() {
			var elem cryptobyte.String
			var tag cbasn1.Tag
			if !tbs.ReadAnyASN1Element(&elem, &tag) {
				seq.SetError(errors.New("tbs: element"))
				return
			}
			if tag != cbasn1.Tag(3).ContextSpecific().Constructed() {
				seq.AddBytes(elem)
				continue
			}
			// [3] EXPLICIT Extensions: SEQUENCE OF Extension.
			var wrapper cryptobyte.String
			var exts cryptobyte.String
			el := elem
			if !el.ReadASN1(&wrapper, tag) || !wrapper.ReadASN1(&exts, cbasn1.SEQUENCE) {
				seq.SetError(errors.New("tbs: extensions"))
				return
			}
			seq.AddASN1(tag, func(w *cryptobyte.Builder) {
				w.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) {
					for !exts.Empty() {
						var ext cryptobyte.String
						if !exts.ReadASN1Element(&ext, cbasn1.SEQUENCE) {
							list.SetError(errors.New("tbs: extension"))
							return
						}
						var body cryptobyte.String
						var oid asn1.ObjectIdentifier
						probe := ext
						if !probe.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&oid) {
							list.SetError(errors.New("tbs: extension oid"))
							return
						}
						if oid.Equal(sctExtensionOID) {
							continue
						}
						list.AddBytes(ext)
					}
				})
			})
		}
	})
	return out.Bytes()
}

// ctCheck evaluates a certificate against the CT policy.
func ctCheck(leaf, issuer *x509.Certificate, logs *LogList, required int) CTStatus {
	scts, err := VerifySCTs(leaf, issuer, logs)
	st := CTStatus{Embedded: len(scts), Required: required, SCTs: scts}
	for _, s := range scts {
		if s.Verified {
			st.Verified++
		}
	}
	switch {
	case err != nil:
		st.Error = err.Error()
	case required == 0:
		st.OK = true
	case logs != nil && issuer != nil && st.Verified < required:
		st.Error = fmt.Sprintf("%d of %d embedded scts verify against the log list, %d required", st.Verified, st.Embedded, required)
	case (logs == nil || issuer == nil) && st.Embedded < required:
		st.Error = fmt.Sprintf("%d embedded scts, %d required", st.Embedded, required)
	default:
		st.OK = true
	}
	return st
}

// uint64 helper kept for tests that build SCTs.
func putUint64(b []byte, v uint64) { binary.BigEndian.PutUint64(b, v) }
