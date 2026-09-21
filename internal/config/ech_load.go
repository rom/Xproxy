package config

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/rom/xproxy/internal/ech"
)

// maxECHFile bounds what is read from an ECH file. Both files are tiny;
// the bound is here so a mistaken path cannot read a disk image.
const maxECHFile = 64 << 10

// LoadECHKey reads a config and private key pair and checks that they
// belong together. Serving a config with the wrong key is the hardest
// ECH fault to notice from outside: every handshake falls back to the
// public name and works, so the site is up, fast, and not encrypting
// its client hellos at all.
func LoadECHKey(configFile, keyFile string) (ech.Config, []byte, error) {
	raw, err := readSmall(configFile)
	if err != nil {
		return ech.Config{}, nil, err
	}
	cfgBytes, err := decodeECHConfig(raw)
	if err != nil {
		return ech.Config{}, nil, fmt.Errorf("config_file %s: %w", configFile, err)
	}
	cfg, err := ech.Parse(cfgBytes)
	if err != nil {
		return ech.Config{}, nil, fmt.Errorf("config_file %s: %w", configFile, err)
	}
	rawKey, err := readSmall(keyFile)
	if err != nil {
		return ech.Config{}, nil, err
	}
	key, err := decodeECHKey(rawKey)
	if err != nil {
		return ech.Config{}, nil, fmt.Errorf("key_file %s: %w", keyFile, err)
	}
	pub, err := ech.PrivateKeyPublic(key)
	if err != nil {
		return ech.Config{}, nil, fmt.Errorf("key_file %s: %w", keyFile, err)
	}
	if !bytes.Equal(pub, cfg.PublicKey) {
		return ech.Config{}, nil, fmt.Errorf("key_file %s does not hold the private key for config_file %s: the public keys differ", keyFile, configFile)
	}
	return cfg, key, nil
}

// ECHConfigBytes re-encodes a loaded config for crypto/tls.
func ECHConfigBytes(c ech.Config) ([]byte, error) { return c.Marshal() }

func readSmall(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxECHFile {
		return nil, fmt.Errorf("%s is %d bytes, which is not an ECH file", path, st.Size())
	}
	return os.ReadFile(path) //nolint:gosec // path from validated configuration
}

// decodeECHConfig accepts the raw wire form or base64 text, because
// both are what an operator ends up with: the raw bytes from keygen, or
// the string they pasted out of a DNS record.
func decodeECHConfig(raw []byte) ([]byte, error) {
	if len(raw) >= 4 && raw[0] == 0xfe {
		return raw, nil
	}
	text := strings.Join(strings.Fields(string(raw)), "")
	text = strings.TrimPrefix(text, "ech=")
	text = strings.Trim(text, `"`)
	dec, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("neither a raw ECHConfig nor base64: %w", err)
	}
	// A pasted record holds a list; take the first config from it.
	if len(dec) >= 2 && dec[0] == 0x00 || (len(dec) >= 4 && dec[2] == 0xfe) {
		if cs, err := ech.ParseList(dec); err == nil && len(cs) > 0 {
			return cs[0].Marshal()
		}
	}
	return dec, nil
}

// decodeECHKey accepts raw 32 bytes, base64, hex, or a PEM block, which
// covers every way a key ends up in a file.
func decodeECHKey(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		return raw, nil
	}
	if blk, _ := pem.Decode(raw); blk != nil {
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			if b, ok := ecdhBytes(k); ok {
				return b, nil
			}
		}
		if len(blk.Bytes) == 32 {
			return blk.Bytes, nil
		}
		return nil, fmt.Errorf("PEM block %q does not hold an X25519 private key", blk.Type)
	}
	text := strings.Join(strings.Fields(string(raw)), "")
	if dec, err := base64.StdEncoding.DecodeString(text); err == nil && len(dec) == 32 {
		return dec, nil
	}
	if dec, err := hex.DecodeString(text); err == nil && len(dec) == 32 {
		return dec, nil
	}
	return nil, fmt.Errorf("not a 32 byte X25519 private key (raw, base64, hex or PEM); the file holds %d bytes", len(raw))
}

// certCovers reports whether a certificate file has a name among its
// subject alternative names. It is used to warn when the ECH public
// name — the one a stale client falls back to — cannot be served here.
func certCovers(path, name string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec // path from validated configuration
	if err != nil {
		return false
	}
	for len(raw) > 0 {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			return false
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		if crt.VerifyHostname(name) == nil {
			return true
		}
		// Only the leaf is considered: an intermediate's names are not
		// names this server can answer to.
		return false
	}
	return false
}

// encodeB64 and encodeHex are here for the tests that write key files
// in the shapes operators actually have.
func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func encodeHex(b []byte) string { return hex.EncodeToString(b) }
