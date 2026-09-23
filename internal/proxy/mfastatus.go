package proxy

import (
	"fmt"
	"sort"
	"time"

	"github.com/rom/xproxy/internal/mfa"
)

// The second factor as the control plane sees it. A listener that asks
// for one implements MFAHolder; the engine asks each of its listeners
// rather than knowing which kinds have a factor.
//
// Enrolments live in a file, and the file is shared by every listener
// configured with the same path -- so enrolling through one listener
// enrols for all of them, while the lockout, which is this process's
// memory rather than the file's, stays per listener. Both facts are in
// the view below so that neither is a surprise.

// MFAListener is one listener's second factor.
type MFAListener struct {
	// Listener is the name in the configuration, and Kind what it
	// serves.
	Listener string `json:"listener"`
	Kind     string `json:"kind"`
	// File is the enrolment file, which more than one listener may
	// share.
	File string `json:"file"`
	// Users is who is enrolled, with what this process remembers.
	Users []mfa.GuardStatus `json:"users"`
}

// MFA describes every listener that asks for a second factor.
func (s *Server) MFA() []MFAListener {
	now := time.Now()
	out := []MFAListener{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bl := range s.listeners {
		h, ok := bl.inst.(MFAHolder)
		if !ok {
			continue
		}
		g := h.MFAGuard()
		if g == nil {
			continue
		}
		out = append(out, MFAListener{
			Listener: bl.cfg.Name, Kind: bl.cfg.Kind,
			File: g.Store().Path(), Users: g.List(now),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Listener < out[j].Listener })
	return out
}

// ErrNoSuchMFAListener says no bound listener by that name asks for a
// second factor.
var ErrNoSuchMFAListener = fmt.Errorf("no listener of that name asks for a second factor")

// mfaGuard finds one listener's guard.
func (s *Server) mfaGuard(listener string) (*mfa.Guard, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bl := range s.listeners {
		if bl.cfg.Name != listener {
			continue
		}
		if h, ok := bl.inst.(MFAHolder); ok {
			if g := h.MFAGuard(); g != nil {
				return g, nil
			}
		}
		break
	}
	return nil, fmt.Errorf("%w: %q", ErrNoSuchMFAListener, listener)
}

// MFAEnrol gives a user a new second factor on a listener and returns
// what has to be shown once: the secret, the URI an authenticator
// reads, and the recovery codes.
func (s *Server) MFAEnrol(listener, user, issuer string, p mfa.Params) (secret, uri string, recovery []string, err error) {
	g, err := s.mfaGuard(listener)
	if err != nil {
		return "", "", nil, err
	}
	secret, recovery, err = g.Store().Enrol(user, p)
	if err != nil {
		return "", "", nil, err
	}
	// A name enrolled again is a new factor, so whatever this process
	// remembered about the old one goes with it.
	g.Forget(user)
	if issuer == "" {
		issuer = "xproxy"
	}
	return secret, mfa.URI(issuer, user, secret, p), recovery, nil
}

// MFARecovery replaces a user's recovery codes and returns the new
// ones.
func (s *Server) MFARecovery(listener, user string) ([]string, error) {
	g, err := s.mfaGuard(listener)
	if err != nil {
		return nil, err
	}
	return g.Store().Recovery(user)
}

// MFARemove takes a user's enrolment away.
func (s *Server) MFARemove(listener, user string) error {
	g, err := s.mfaGuard(listener)
	if err != nil {
		return err
	}
	if err := g.Store().Remove(user); err != nil {
		return err
	}
	// The lockout and the replay memory go too: leaving them would
	// meet the next person enrolled under this name.
	g.Forget(user)
	return nil
}

// MFAUnlock lets a user try again, which is what an operator does for
// somebody whose authenticator drifted.
func (s *Server) MFAUnlock(listener, user string) (bool, error) {
	g, err := s.mfaGuard(listener)
	if err != nil {
		return false, err
	}
	return g.Unlock(user), nil
}
