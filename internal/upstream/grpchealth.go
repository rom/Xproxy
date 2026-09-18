package upstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// The gRPC health protocol (grpc.health.v1.Health/Check) hand encoded:
// HealthCheckRequest has one string field (1, service) and
// HealthCheckResponse one enum field (1, status) where 1 is SERVING. A
// gRPC message on the wire is a one byte compression flag, a four byte
// big endian length and the protobuf bytes.

// HealthCheckPath is the method of the standard health service.
const HealthCheckPath = "/grpc.health.v1.Health/Check"

// EncodeHealthCheckRequest frames a HealthCheckRequest for service.
func EncodeHealthCheckRequest(service string) []byte {
	var msg []byte
	if service != "" {
		msg = append(msg, 0x0a) // field 1, wire type 2
		msg = appendVarint(msg, uint64(len(service)))
		msg = append(msg, service...)
	}
	return FrameGRPC(msg)
}

// FrameGRPC prefixes a protobuf message with the gRPC length prefix.
func FrameGRPC(msg []byte) []byte {
	out := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg))) //nolint:gosec // bounded by the caller
	return append(out, msg...)
}

// EncodeHealthCheckResponse frames a HealthCheckResponse with status.
func EncodeHealthCheckResponse(status int) []byte {
	msg := appendVarint([]byte{0x08}, uint64(status)) //nolint:gosec // small enum
	return FrameGRPC(msg)
}

// ParseHealthCheckResponse reads one framed HealthCheckResponse and
// returns its status (1 is SERVING).
func ParseHealthCheckResponse(body []byte) (int, error) {
	if len(body) < 5 {
		return 0, errors.New("short gRPC frame")
	}
	if body[0] != 0 {
		return 0, errors.New("compressed gRPC frame")
	}
	n := binary.BigEndian.Uint32(body[1:5])
	if int(n) > len(body)-5 || n > 1<<20 {
		return 0, errors.New("truncated gRPC frame")
	}
	msg := body[5 : 5+n]
	status := 0 // UNKNOWN when absent
	for len(msg) > 0 {
		tag, k := binary.Uvarint(msg)
		if k <= 0 {
			return 0, errors.New("bad protobuf tag")
		}
		msg = msg[k:]
		field, wire := tag>>3, tag&7
		switch wire {
		case 0:
			v, k := binary.Uvarint(msg)
			if k <= 0 {
				return 0, errors.New("bad varint")
			}
			msg = msg[k:]
			if field == 1 {
				status = int(v) //nolint:gosec // enum
			}
		case 2:
			l, k := binary.Uvarint(msg)
			if k <= 0 || l > 1<<20 || int(l) > len(msg)-k { //nolint:gosec // bounded just above
				return 0, errors.New("bad length")
			}
			msg = msg[k+int(l):] //nolint:gosec // bounded above
		default:
			return 0, errors.New("unsupported wire type")
		}
	}
	return status, nil
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// probeGRPC performs one health Check and reports SERVING. The response
// status may arrive as a trailer (normal) or as a header (trailers-only
// error response).
func (p *Pool) probeGRPC(ctx context.Context, client *http.Client, base string) bool {
	hc := p.Cfg.HealthCheck
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+HealthCheckPath, bytes.NewReader(EncodeHealthCheckRequest(hc.GRPCService)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("User-Agent", "xproxy-health/1")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	code := resp.Header.Get("Grpc-Status")
	if code == "" {
		code = resp.Trailer.Get("Grpc-Status")
	}
	if c, err := strconv.Atoi(code); err != nil || c != 0 {
		return false
	}
	st, err := ParseHealthCheckResponse(body)
	return err == nil && st == 1
}
