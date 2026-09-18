package upstream

import "testing"

func TestGRPCHealthEncoding(t *testing.T) {
	req := EncodeHealthCheckRequest("echo.Echo")
	if req[0] != 0 || int(req[4]) != len(req)-5 || string(req[7:]) != "echo.Echo" {
		t.Fatalf("request: %x", req)
	}
	if empty := EncodeHealthCheckRequest(""); len(empty) != 5 {
		t.Fatalf("empty request: %x", empty)
	}
	for _, st := range []int{0, 1, 2, 3, 300} {
		got, err := ParseHealthCheckResponse(EncodeHealthCheckResponse(st))
		if err != nil || got != st {
			t.Fatalf("round trip %d: %d %v", st, got, err)
		}
	}
	// Unknown fields are skipped; bad frames are refused.
	msg := append([]byte{0x12, 0x02, 'h', 'i', 0x08, 0x01}, []byte{}...)
	if got, err := ParseHealthCheckResponse(FrameGRPC(msg)); err != nil || got != 1 {
		t.Fatalf("with unknown field: %d %v", got, err)
	}
	for _, bad := range [][]byte{{}, {1, 0, 0, 0, 0}, {0, 0, 0, 0, 9, 1}, FrameGRPC([]byte{0x08}), FrameGRPC([]byte{0x12, 0x09, 'x'}), FrameGRPC([]byte{0x0d, 0, 0, 0, 0})} {
		if _, err := ParseHealthCheckResponse(bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}
