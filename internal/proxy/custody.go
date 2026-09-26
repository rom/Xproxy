package proxy

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/fipsmode"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/tlsconf"
)

// newSecrets builds the resolver every configured reference is answered from.
//
// There is always a resolver, even with no secrets section, so that no call site
// has to test for nil: without one it answers file: and env: references and
// refuses vault: ones, which is what a configuration written before references
// existed needs.
func newSecrets(cfg *config.Config, logs *logging.Logs) (*keysource.Resolver, error) {
	sec := cfg.Secrets
	// A refresh that fails keeps the previous value, so the operator has to
	// be told: a secret that silently stops rotating is the failure mode
	// this arrangement is most likely to hide.
	warn := func(ref string, err error) {
		logs.Error.Warn("secret refresh failed; the previous value stays in force",
			"reference", ref, "error", err.Error())
	}
	if sec == nil {
		return keysource.New(nil, 0, warn), nil
	}
	var v *keysource.Vault
	if vs := sec.Vault; vs != nil {
		var err error
		v, err = keysource.NewVault(keysource.VaultConfig{
			Address:    vs.Address,
			Mount:      vs.Mount,
			KVVersion:  vs.KVVersion,
			TokenRef:   vaultTokenRef(vs),
			Namespace:  vs.Namespace,
			CAFile:     vs.CAFile,
			ServerName: vs.ServerName,
			Insecure:   vs.Insecure && vs.AllowInsecure,
		})
		if err != nil {
			return nil, fmt.Errorf("secrets.vault: %w", err)
		}
	}
	return keysource.New(v, sec.RefreshInterval.D(), warn), nil
}

// vaultTokenRef turns the two token settings into the one reference the vault
// client takes. Validation has already refused both being set.
func vaultTokenRef(vs *config.VaultSecrets) string {
	if vs.TokenEnv != "" {
		return keysource.SchemeEnv + ":" + vs.TokenEnv
	}
	if vs.TokenFile != "" {
		return keysource.SchemeFile + ":" + vs.TokenFile
	}
	return ""
}

// fipsStatus applies the fips section at start.
//
// Required and not active is a refusal, not a warning: the whole value of the
// setting is that a deployment which must be FIPS cannot quietly stop being it
// after a rebuild without the right toolchain. The probe is separate and says
// which of the configured algorithms the active module will actually do, because
// a key exchange list and a cipher suite list that the module refuses is a
// listener that handshakes with nothing -- and that is worth knowing at start
// rather than from the first client.
func fipsStatus(cfg *config.Config, logs *logging.Logs) (fipsmode.Status, error) {
	f := cfg.FIPS
	if f == nil {
		return fipsmode.Status{Enabled: fipsmode.Enabled()}, nil
	}
	if err := fipsmode.Require(f.Required); err != nil {
		return fipsmode.Status{}, err
	}
	st := fipsmode.Status{Enabled: fipsmode.Enabled(), Required: f.Required}
	if f.Probe == nil || !*f.Probe {
		return st, nil
	}
	groups, suites := fipsProbeSubjects(cfg)
	refused, err := fipsmode.Probe(groups, suites)
	if err != nil {
		return fipsmode.Status{}, fmt.Errorf("fips.probe: %w", err)
	}
	st.Probed = true
	st.Refused = refused
	if len(refused) == 0 {
		logs.Security.Info("fips probe: every configured algorithm is available",
			"enabled", st.Enabled, "groups", len(groups), "suites", len(suites))
		return st, nil
	}
	if f.ProbeFails {
		return fipsmode.Status{}, fmt.Errorf("fips.probe: the active module refuses %d configured algorithm(s): %v",
			len(refused), refused)
	}
	logs.Security.Warn("fips probe: the active module refuses configured algorithms, which clients asking for them "+
		"cannot handshake with", "refused", refused)
	return st, nil
}

// fipsProbeSubjects collects every key exchange group and cipher suite any TLS
// listener names, deduplicated. What is not named is not probed: a default the
// proxy never offers is not worth a handshake.
func fipsProbeSubjects(cfg *config.Config) ([]tls.CurveID, []uint16) {
	seenG := map[tls.CurveID]bool{}
	seenS := map[uint16]bool{}
	var groups []tls.CurveID
	var suites []uint16
	for i := range cfg.Server.Listeners {
		t := cfg.Server.Listeners[i].TLS
		if t == nil {
			continue
		}
		ids, err := config.CurveIDs(t.KeyExchange)
		if err != nil {
			// Validation refuses an unknown group, so this cannot be a
			// surprise here; skip rather than fail the probe.
			continue
		}
		for _, id := range ids {
			if !seenG[id] {
				seenG[id] = true
				groups = append(groups, id)
			}
		}
		for _, id := range tlsconf.SuiteIDs(t.CipherSuites) {
			if !seenS[id] {
				seenS[id] = true
				suites = append(suites, id)
			}
		}
	}
	return groups, suites
}

// secretRefresh is the loop that carries a rotated secret into a running
// listener.
//
// It exists because a certificate is read once at load: without it, a key
// rotated in the vault would reach the listener only at the next reload, and
// "rotate and the proxy picks it up" would be a claim rather than a behaviour.
//
// It runs at the refresh interval and only where a certificate's key is a
// reference; a listener whose keys are all files or signers gets no goroutine.
// A failure leaves the certificates in force alone and is warned about, which is
// the same rule the resolver holds to: a vault that is down must not take a key
// away from a proxy that is serving with it.
type secretRefresh struct {
	every time.Duration
	logs  *logging.Logs
	get   func() []*boundListener
	done  chan struct{}
	wg    sync.WaitGroup
	// rotations counts the certificates actually replaced, for the status
	// view -- a number an operator can compare against what the vault says
	// it rotated.
	rotations atomic.Uint64
	// failures counts the refreshes that could not resolve.
	failures atomic.Uint64
}

func newSecretRefresh(every time.Duration, logs *logging.Logs, get func() []*boundListener) *secretRefresh {
	if every <= 0 {
		every = config.DefaultSecretRefresh
	}
	return &secretRefresh{every: every, logs: logs, get: get, done: make(chan struct{})}
}

func (r *secretRefresh) start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.every)
		defer t.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-t.C:
				r.once()
			}
		}
	}()
}

func (r *secretRefresh) stop() {
	close(r.done)
	r.wg.Wait()
}

// once asks every listener with a referenced key whether its key changed.
func (r *secretRefresh) once() {
	for _, bl := range r.get() {
		rl := bl.tlsReload
		if rl == nil || !rl.HasReferencedKeys() {
			continue
		}
		changed, err := rl.RefreshSecrets()
		switch {
		case err != nil:
			r.failures.Add(1)
			r.logs.Error.Warn("a referenced certificate key could not be refreshed; the certificate in force stays",
				"listener", bl.cfg.Name, "error", err.Error())
		case changed:
			r.rotations.Add(1)
			// The security log, not the error log: a key rotating is a
			// custody event and belongs beside the others.
			r.logs.Security.Info("certificate key rotated from its reference", "listener", bl.cfg.Name)
		}
	}
}
