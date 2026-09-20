package sensitive

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http/httptest"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// zeroReader is an endless stream of one byte, which every compressor
// reduces to almost nothing.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// lowerFloor shrinks the ratio floor for one test so the same code path
// runs on a body small enough to stay quick under the race detector.
func lowerFloor(t *testing.T, to int64) {
	t.Helper()
	was := ratioFloor
	ratioFloor = to
	t.Cleanup(func() { ratioFloor = was })
}

func bomb(t *testing.T, plain int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(w, zeroReader{}, plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestStreamedDecodeBoundsRatio: a compressed body is forwarded decoded,
// so its decoded size must be bounded by the ratio and not only by the
// body limit its compressed form passed. Before the bound, a couple of
// kilobytes of zstd became the whole plaintext toward the upstream; the
// measured worst case on the real filter was 32,742 to 1. The bomb here
// is kept to 64 MiB so the test stays quick under the race detector:
// the cut happens just past the 8 MiB floor either way.
func TestStreamedDecodeBoundsRatio(t *testing.T) {
	lowerFloor(t, 64<<10)
	const plain = 4 << 20
	// max_bytes keeps max_decoded_bytes (four times it) below the bomb's
	// plaintext, which is what puts the body on the streaming path.
	const maxBytes = 64 << 10
	body := bomb(t, plain)
	f, err := filtertest.Build("sensitive_data", "dlp", filter.Options{
		"request":  map[string]any{"scan": []any{"body"}, "action": "log", "types": []any{"text/plain"}, "max_bytes": maxBytes},
		"response": map[string]any{"scan": []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://app.test/upload", bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Content-Encoding", "zstd")
	r.ContentLength = int64(len(body))
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	n, err := io.Copy(io.Discard, r.Body)
	if err == nil {
		t.Fatalf("the whole bomb was forwarded: %d bytes", n)
	}
	if err.Error() != ErrBomb.Error() {
		t.Fatalf("cut with %v, want %v", err, ErrBomb)
	}
	// Cut soon after the floor, nowhere near the whole bomb.
	if n >= plain/4 {
		t.Fatalf("forwarded %d of %d bytes before the cut", n, plain)
	}
	t.Logf("%d compressed bytes yielded %d bytes before the cut (bomb held %d)", len(body), n, plain)
}

// TestStreamedDecodePassesOrdinaryBodies: a large but ordinary
// compressed body (well under the ratio) still streams through whole.
func TestStreamedDecodePassesOrdinaryBodies(t *testing.T) {
	// Text that compresses a few times over, not a hundred: well past
	// the floor and well inside the ratio, which is the
	// case that must stream through whole. A repeated sentence would
	// compress far past the bound and prove nothing, so the corpus is
	// deterministic pseudo-random words.
	lowerFloor(t, 64<<10)
	var plainBuf bytes.Buffer
	rnd := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test corpus, not a secret
	for plainBuf.Len() < 256<<10 {
		fmt.Fprintf(&plainBuf, "%x %x %x %x\n", rnd.Uint64(), rnd.Uint64(), rnd.Uint64(), rnd.Uint64())
	}
	plain := plainBuf.Bytes()
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if buf.Len()*100 < len(plain) {
		t.Fatalf("test corpus of %d bytes compresses to %d, past the bound the filter refuses: the test would prove nothing", len(plain), buf.Len())
	}
	f, err := filtertest.Build("sensitive_data", "dlp", filter.Options{
		"request":  map[string]any{"scan": []any{"body"}, "action": "log", "types": []any{"text/plain"}, "max_bytes": 32 << 10},
		"response": map[string]any{"scan": []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://app.test/upload", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Content-Encoding", "zstd")
	r.ContentLength = int64(buf.Len())
	filtertest.Run(f, r, nil)
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil || n != int64(len(plain)) {
		t.Fatalf("ordinary body cut: %d of %d bytes, err %v", n, len(plain), err)
	}
}

// TestMaxDecompressionRatioValidation pins the option's bounds.
func TestMaxDecompressionRatioValidation(t *testing.T) {
	for _, bad := range []any{1, 100001, -5} {
		if _, err := filtertest.Build("sensitive_data", "dlp", filter.Options{
			"request": map[string]any{"scan": []any{"body"}, "max_decompression_ratio": bad},
		}); err == nil {
			t.Errorf("ratio %v accepted", bad)
		}
	}
	if _, err := filtertest.Build("sensitive_data", "dlp", filter.Options{
		"request": map[string]any{"scan": []any{"body"}, "max_decompression_ratio": 20},
	}); err != nil {
		t.Errorf("ratio 20 refused: %v", err)
	}
}
