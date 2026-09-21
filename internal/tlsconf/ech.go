package tlsconf

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/ech"
)

// Encrypted Client Hello, server side.
//
// The keys live behind an atomic pointer and are handed to crypto/tls
// through GetEncryptedClientHelloKeys rather than the static field, so
// a reload swaps them without rebuilding the listener — which is the
// whole point of an ECH rotation: publish the new config in DNS, serve
// both keys until the old record's TTL has passed everywhere, then drop
// the old one.

// echKeys is the loaded set for one listener.
type echKeys struct {
	keys []tls.EncryptedClientHelloKey
	info []ECHKeyInfo
	// require refuses a handshake that did not use ECH.
	require bool
}

// ECHKeyInfo is one key in the management view.
type ECHKeyInfo struct {
	ConfigID   uint8  `json:"config_id"`
	PublicName string `json:"public_name"`
	Retry      bool   `json:"retry"`
	ConfigFile string `json:"config_file"`
}

// ECHStatus is the listener's ECH state.
type ECHStatus struct {
	Enabled  bool         `json:"enabled"`
	Require  bool         `json:"require"`
	Keys     []ECHKeyInfo `json:"keys"`
	Accepted uint64       `json:"accepted"`
	Rejected uint64       `json:"rejected"`
	Refused  uint64       `json:"refused"`
	// ConfigList is the base64 ECHConfigList to publish in the HTTPS
	// record, so the value served and the value published cannot drift
	// apart without somebody noticing.
	ConfigList string `json:"config_list,omitempty"`
}

// ReloadECH re-reads the key files, for `xproxyctl reload-certs`: an
// ECH key is rotated on the same schedule as a certificate, and for the
// same reason, so it reloads the same way. The counters are kept, since
// nothing about the traffic changed.
func (r *Reloadable) ReloadECH() error {
	if r.echCfg == nil {
		return nil
	}
	keys, err := loadECH(r.echCfg)
	if err != nil {
		return err
	}
	r.ech.Store(keys)
	return nil
}

// loadECH reads the configured keys.
func loadECH(c *config.ECH) (*echKeys, error) {
	if c == nil || len(c.Keys) == 0 {
		return nil, nil
	}
	out := &echKeys{require: c.Require}
	for i := range c.Keys {
		k := &c.Keys[i]
		cfg, priv, err := config.LoadECHKey(k.ConfigFile, k.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("ech keys[%d]: %w", i, err)
		}
		enc, err := cfg.Marshal()
		if err != nil {
			return nil, fmt.Errorf("ech keys[%d]: %w", i, err)
		}
		out.keys = append(out.keys, tls.EncryptedClientHelloKey{
			Config: enc, PrivateKey: priv, SendAsRetry: k.RetryOffered(),
		})
		out.info = append(out.info, ECHKeyInfo{
			ConfigID: cfg.ID, PublicName: cfg.PublicName,
			Retry: k.RetryOffered(), ConfigFile: k.ConfigFile,
		})
	}
	return out, nil
}

// configList re-encodes the served keys as the list to publish.
func (e *echKeys) configList() string {
	if e == nil {
		return ""
	}
	cs := make([]ech.Config, 0, len(e.keys))
	for _, k := range e.keys {
		c, err := ech.Parse(k.Config)
		if err != nil {
			continue
		}
		cs = append(cs, c)
	}
	s, err := ech.ListBase64(cs)
	if err != nil {
		return ""
	}
	return s
}

// ECH reports the listener's state, nil when the section is absent.
func (r *Reloadable) ECH() *ECHStatus {
	e := r.ech.Load()
	if e == nil {
		return nil
	}
	return &ECHStatus{
		Enabled: true, Require: e.require, Keys: e.info,
		Accepted: r.echAccepted.Load(), Rejected: r.echRejected.Load(),
		Refused: r.echRefused.Load(), ConfigList: e.configList(),
	}
}

// ECHKeys is the GetEncryptedClientHelloKeys hook: it reads the current
// set on every attempt, so a reload takes effect on the next handshake.
func (r *Reloadable) ECHKeys(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
	e := r.ech.Load()
	if e == nil {
		// No keys: the client's ECH is rejected and it falls back, the
		// same as any server that does not offer ECH.
		return nil, nil
	}
	return e.keys, nil
}

// verifyECH runs after the handshake's crypto and before it completes.
// It is where `require` is enforced, because whether ECH was accepted
// is not known any earlier.
func (r *Reloadable) verifyECH(cs tls.ConnectionState) error {
	e := r.ech.Load()
	if e == nil {
		return nil
	}
	if cs.ECHAccepted {
		r.echAccepted.Add(1)
		return nil
	}
	// The client either did not try, or tried with a key this server
	// does not hold. Both land here; the retry config sent during the
	// handshake is what fixes the second case on the next attempt.
	r.echRejected.Add(1)
	if e.require {
		r.echRefused.Add(1)
		return ErrECHRequired
	}
	return nil
}

// base64Decode is here so tests can read back the published list
// without importing encoding/base64 into every file that needs it.
func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
