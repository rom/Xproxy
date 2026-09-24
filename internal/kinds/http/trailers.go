package http

import (
	"io"
	"net/http"
)

// Trailers are the fields an upstream sends after the body, when it only
// knows them then: a checksum, a signature, gRPC's status. A route that
// does not want them gets them removed, both the announcement and the
// fields, because an announced trailer with nothing behind it leaves a
// client waiting for a field that never arrives.
//
// Removing them has to happen where they are read, not where the response
// header is: the transport fills Response.Trailer at the end of the body,
// after everything that inspects the response has run, and the reverse
// proxy then forwards whatever is in the map -- announced or not. So the
// body is wrapped, and the map emptied at the end of it.

// stripTrailers removes the announcement and arranges for the fields to be
// gone by the time the response is forwarded.
func stripTrailers(resp *http.Response) {
	resp.Header.Del("Trailer")
	resp.Trailer = nil
	if resp.Body != nil {
		resp.Body = &trailerStripper{ReadCloser: resp.Body, resp: resp}
	}
}

type trailerStripper struct {
	io.ReadCloser
	resp *http.Response
	done bool
}

func (t *trailerStripper) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if err != nil && !t.done {
		// The end of the body is where the transport has just written
		// the trailers into the response. Emptying the map rather than
		// replacing it matters: the transport holds the same map.
		t.done = true
		for k := range t.resp.Trailer {
			delete(t.resp.Trailer, k)
		}
		t.resp.Trailer = nil
	}
	return n, err
}
