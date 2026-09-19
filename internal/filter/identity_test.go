package filter

import (
	"context"
	"testing"
)

func TestIdentitySet(t *testing.T) {
	base := context.Background()
	// Without a set attached, SetIdentity is a no-op and Get is "".
	SetIdentity(base, "jwt", "x")
	ctx, id := WithIdentity(base)
	if id.Get("jwt") != "" || id.Any() != "" {
		t.Fatal("fresh set not empty")
	}
	SetIdentity(ctx, "jwt", "sub-1")
	SetIdentity(ctx, "api_key", "svc")
	SetIdentity(ctx, "", "ignored")
	SetIdentity(ctx, "empty", "")
	if id.Get("jwt") != "sub-1" || id.Get("api_key") != "svc" || id.Get("empty") != "" {
		t.Fatalf("recorded %+v", id)
	}
	if id.Any("oidc", "api_key") != "svc" {
		t.Fatalf("preference order: %q", id.Any("oidc", "api_key"))
	}
	// The last value for a kind wins.
	SetIdentity(ctx, "jwt", "sub-2")
	if id.Get("jwt") != "sub-2" {
		t.Fatalf("overwrite: %q", id.Get("jwt"))
	}
	var nilID *Identity
	if nilID.Get("jwt") != "" || nilID.Any() != "" {
		t.Fatal("nil identity not empty")
	}
}
