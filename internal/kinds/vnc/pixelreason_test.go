package vnc

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/rom/xproxy/internal/rfb"
)

// The word an operator queries by, for each bound on the pixel path.
//
// Every string here is a counter name and a security event's reason, so the
// mapping is part of the interface this listener has with whoever is reading its
// records during an incident -- and the empty answer is load-bearing in the
// other direction: a stream that simply ended is not a refusal, and a mapping
// that invented a reason for it would put a refusal in the record for every
// client that disconnected.
func TestEveryPixelBoundHasTheWordItIsQueriedBy(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{rfb.ErrFramebufferTooLarge, "framebuffer_too_large"},
		{rfb.ErrRectanglePixels, "rectangle_too_large"},
		{rfb.ErrRectangleOutside, "rectangle_outside_framebuffer"},
		{rfb.ErrTooManyRectangles, "too_many_rectangles"},
		{rfb.ErrRectangleTooLarge, "encoded_rectangle_too_large"},
		{rfb.ErrDecodeRatio, "decode_ratio"},
		{rfb.ErrCutTextTooLarge, "cut_text_too_large"},
		{rfb.ErrUnframable, "unframable"},
	} {
		if got := pixelReason(c.err); got != c.want {
			t.Errorf("%v is reported as %q, want %q", c.err, got, c.want)
		}
		// Wrapped, which is how it actually arrives: the reader says which
		// numbers were involved and wraps the sentinel.
		wrapped := fmt.Errorf("rectangle 3 of 4: %w", c.err)
		if got := pixelReason(wrapped); got != c.want {
			t.Errorf("a wrapped %v is reported as %q, want %q", c.err, got, c.want)
		}
	}
	// The end of a stream is not a refusal, and neither is anything else this
	// mapping has no word for.
	for _, err := range []error{nil, io.EOF, io.ErrUnexpectedEOF,
		errors.New("connection reset by peer")} {
		if got := pixelReason(err); got != "" {
			t.Errorf("%v is reported as a refusal %q", err, got)
		}
	}
}
