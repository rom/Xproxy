package netutil

import "testing"

func TestPathTemplate(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "/"},
		{"/users", "/users"},
		{"/users/42", "/users/*"},
		{"/users/42/orders/7", "/users/*/orders/*"},
		{"/items/123e4567-e89b-12d3-a456-426614174000", "/items/*"},
		{"/blobs/8f1c2d3e4a5b6c7d8e9f0a1b2c3d4e5f", "/blobs/*"},
		{"/tokens/dGhpcyBpcyBhIHRlc3Q1234567890", "/tokens/*"},
		{"/assets/app.js", "/assets/app.js"},
		{"/reports/2024.pdf", "/reports/*"},
		{"/v1/customers/acme/invoices", "/v1/customers/acme/invoices"},
		{"/api/v2/items", "/api/v2/items"},
		{"/files/report-final.tar.gz", "/files/report-final.tar.gz"},
	} {
		if got := PathTemplate(tc.in); got != tc.want {
			t.Errorf("PathTemplate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
