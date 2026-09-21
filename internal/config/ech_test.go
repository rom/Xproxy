package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/ech"
	"github.com/rom/xproxy/internal/testutil"
)

// echFiles writes a config and key pair and returns their paths.
func echFiles(t *testing.T, dir, publicName string, id uint8, mode os.FileMode) (string, string) {
	t.Helper()
	cfg, priv, err := ech.Generate(publicName, id)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(dir, publicName+"-"+string(rune('0'+id))+".echconfig")
	kp := filepath.Join(dir, publicName+"-"+string(rune('0'+id))+".key")
	if err := os.WriteFile(cp, enc, 0o644); err != nil { //nolint:gosec // public by design
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, priv, mode); err != nil {
		t.Fatal(err)
	}
	return cp, kp
}

func echYAML(t *testing.T, cert, key string, keys string, require bool) []byte {
	t.Helper()
	req := "false"
	if require {
		req = "true"
	}
	return []byte(`version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:8443"
      tls:
        certificates: [{cert_file: ` + cert + `, key_file: ` + key + `}]
        ech:
          require: ` + req + `
          keys:
` + keys + `
upstreams:
  - name: app
    endpoints: [{address: "10.0.0.1:80"}]
routes:
  - name: app
    paths: [/]
    upstream: app
`)
}

func TestECHValidation(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ech.example.com")
	cp, kp := echFiles(t, dir, "ech.example.com", 1, 0o600)

	c, err := Parse(echYAML(t, cert, key, "            - {config_file: "+cp+", key_file: "+kp+"}", false))
	if err != nil {
		t.Fatalf("a valid ech section was refused: %v", err)
	}
	if a := strings.Join(c.Advice(), "\n"); a != "" {
		t.Errorf("unexpected advice: %q", a)
	}

	// Two keys sharing a config id: a client echoes the id, so half the
	// handshakes would reach for the wrong key.
	cp2, kp2 := echFiles(t, dir, "ech.example.com", 1, 0o600)
	two := "            - {config_file: " + cp + ", key_file: " + kp + "}\n" +
		"            - {config_file: " + cp2 + ", key_file: " + kp2 + "}"
	if _, err := Parse(echYAML(t, cert, key, two, false)); err == nil {
		t.Error("two keys with the same config id were accepted")
	} else if !strings.Contains(err.Error(), "config id") {
		t.Errorf("the error does not name the cause: %v", err)
	}

	// A private key anyone can read.
	_, worldKey := echFiles(t, dir, "ech.example.com", 2, 0o644)
	cpw, _ := echFiles(t, dir, "ech.example.com", 3, 0o600)
	if _, err := Parse(echYAML(t, cert, key, "            - {config_file: "+cpw+", key_file: "+worldKey+"}", false)); err == nil {
		t.Error("a world readable ech key was accepted")
	}

	// A config whose public name this listener cannot serve: the stale
	// client falls back to it and meets a certificate error.
	cpo, kpo := echFiles(t, dir, "other.example.com", 4, 0o600)
	c, err = Parse(echYAML(t, cert, key, "            - {config_file: "+cpo+", key_file: "+kpo+"}", false))
	if err != nil {
		t.Fatalf("refused rather than advised: %v", err)
	}
	if a := strings.Join(c.Advice(), "\n"); !strings.Contains(a, "public name") {
		t.Errorf("no advice about the uncovered public name: %q", a)
	}

	// require says what it costs.
	c, err = Parse(echYAML(t, cert, key, "            - {config_file: "+cp+", key_file: "+kp+"}", true))
	if err != nil {
		t.Fatal(err)
	}
	if a := strings.Join(c.Advice(), "\n"); !strings.Contains(a, "require") {
		t.Errorf("no advice about require: %q", a)
	}

	// A config file that is not one.
	junk := filepath.Join(dir, "junk.echconfig")
	if err := os.WriteFile(junk, []byte("not an ech config"), 0o644); err != nil { //nolint:gosec // test input
		t.Fatal(err)
	}
	if _, err := Parse(echYAML(t, cert, key, "            - {config_file: "+junk+", key_file: "+kp+"}", false)); err == nil {
		t.Error("a junk config file was accepted")
	}
}

// TestECHKeyFormats: an operator ends up with the key in whatever form
// their tooling produced, and each of them has to load.
func TestECHKeyFormats(t *testing.T) {
	dir := t.TempDir()
	cfg, priv, err := ech.Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	list, err := ech.ListBase64([]ech.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rawCfg := write("raw.echconfig", enc)
	b64Cfg := write("b64.echconfig", []byte(encodeB64(enc)+"\n"))
	listCfg := write("list.echconfig", []byte(`ech="`+list+`"`))
	rawKey := write("raw.key", priv)
	b64Key := write("b64.key", []byte(encodeB64(priv)+"\n"))
	hexKey := write("hex.key", []byte(encodeHex(priv)))

	for _, c := range []struct{ name, cfgPath, keyPath string }{
		{"raw", rawCfg, rawKey},
		{"base64", b64Cfg, b64Key},
		{"a pasted record and a hex key", listCfg, hexKey},
	} {
		got, key, err := LoadECHKey(c.cfgPath, c.keyPath)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got.ID != 1 || got.PublicName != "ech.example.com" || len(key) != 32 {
			t.Errorf("%s: loaded %+v", c.name, got)
		}
	}

	// A pair that does not belong together is the fault that hides: the
	// site works, falls back on every ECH attempt, and encrypts nothing.
	_, otherPriv, err := ech.Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	other := write("other.key", otherPriv)
	if _, _, err := LoadECHKey(rawCfg, other); err == nil {
		t.Error("a mismatched config and key pair loaded")
	} else if !strings.Contains(err.Error(), "public keys differ") {
		t.Errorf("the error does not explain the mismatch: %v", err)
	}
}
