package upstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The layer 4 probes, for the pools a kind: tcp or kind: udp listener
// uses. There is no request to make there, so what a probe can prove is
// narrower and the two protocols differ in how much:
//
//   - A TCP connect proves something accepted, which for a relayed
//     protocol this proxy does not speak is usually all there is to
//     know without speaking it.
//   - A UDP socket accepts nothing. A datagram to a port with no
//     listener produces an ICMP port unreachable that the sender may or
//     may not be told about, may be filtered anywhere on the path, and
//     says nothing at all about a process that is bound but wedged. So
//     the probe sends a question the service answers, and silence is the
//     failure.

// probeTCP dials the endpoint and closes it.
func (p *Pool) probeTCP(ctx context.Context, address string) bool {
	d := net.Dialer{Timeout: p.Cfg.HealthCheck.Timeout.D()}
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// probeUDP sends the configured datagram and waits for an answer,
// requiring what expect says of it.
func (p *Pool) probeUDP(ctx context.Context, address string) bool {
	hc := p.Cfg.HealthCheck
	ra, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return false
	}
	d := net.Dialer{Timeout: hc.Timeout.D()}
	conn, err := d.DialContext(ctx, "udp", ra.String())
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(hc.Timeout.D())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(probeSend(hc)); err != nil {
		return false
	}
	// A connected socket, so an answer from anywhere but the endpoint is
	// dropped by the kernel: a third party cannot vouch for a backend.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	want := probeExpect(hc)
	return len(want) == 0 || bytes.Contains(buf[:n], want)
}

// probeSend is the datagram a udp probe sends. Validation has already
// refused a hex string that is not one, so a decode error here cannot
// happen and an empty payload is the safe reading of one if it did.
func probeSend(hc *config.HealthCheck) []byte {
	if hc.SendHex != "" {
		b, err := hex.DecodeString(hc.SendHex)
		if err != nil {
			return nil
		}
		return b
	}
	return []byte(hc.Send)
}

// probeExpect is what the answer must contain, empty for any answer.
func probeExpect(hc *config.HealthCheck) []byte {
	if hc.ExpectHex != "" {
		b, err := hex.DecodeString(hc.ExpectHex)
		if err != nil {
			return nil
		}
		return b
	}
	return []byte(hc.Expect)
}
