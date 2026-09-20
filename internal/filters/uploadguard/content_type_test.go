package uploadguard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// TestMalformedMultipartTypeRefused: a multipart Content-Type Go's parser
// refuses (a duplicate boundary, a stray parameter) is one most upload
// parsers still accept, so passing it through would skip every check.
func TestMalformedMultipartTypeRefused(t *testing.T) {
	f := build(t, filter.Options{"allowed_extensions": []any{"png"}, "fields": []any{"file"}})
	upload := multipartRequest(t, part{"file", "evil.exe", "", peBytes})
	body, _ := readAll(upload)
	real := upload.Header.Get("Content-Type")
	for _, ct := range []string{
		"multipart/form-data; boundary=decoy; " + real[len("multipart/form-data; "):],
		real + "; x",
		"Multipart/Form-Data; boundary=\"a\"; boundary=\"b\"",
	} {
		r := httptest.NewRequest("POST", "http://app.test/upload", bytes.NewReader(body))
		r.Header.Set("Content-Type", ct)
		v := filtertest.Run(f, r, nil).Request
		if !v.Deny || v.Status != http.StatusBadRequest || v.Detail != "multipart_content_type" {
			t.Errorf("%q: %+v", ct, v)
		}
	}
	// A malformed non-multipart type is not this filter's business.
	r := httptest.NewRequest("POST", "http://app.test/upload", bytes.NewReader([]byte("x")))
	r.Header.Set("Content-Type", "text/plain; charset")
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("plain body refused: %+v", v)
	}
}

func readAll(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}
