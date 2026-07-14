package auth

import (
	"testing"
	"time"
)

func TestJWT_RoundTrip(t *testing.T) {
	issuer := NewIssuer("secret-32-bytes-minimum-length!!", "fraud-test")
	verifier := NewJWTVerifier("secret-32-bytes-minimum-length!!", "fraud-test")

	p := Principal{ID: "u1", Role: RoleAnalyst, TenantID: "t1"}
	token, err := issuer.IssueToken(p, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	out, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.ID != "u1" || out.Role != RoleAnalyst || out.TenantID != "t1" {
		t.Fatalf("wrong principal: %+v", out)
	}
}

func TestJWT_Expired(t *testing.T) {
	issuer := NewIssuer("secret-32-bytes-minimum-length!!", "fraud-test")
	verifier := NewJWTVerifier("secret-32-bytes-minimum-length!!", "fraud-test")

	token, _ := issuer.IssueToken(Principal{ID: "u1", Role: RoleService}, -time.Minute)
	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	issuer := NewIssuer("secret-32-bytes-minimum-length!!", "fraud-test")
	verifier := NewJWTVerifier("different-secret-32-bytes-min!!!", "fraud-test")

	token, _ := issuer.IssueToken(Principal{ID: "u1"}, time.Hour)
	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("expected invalid signature error")
	}
}

func TestAPIKey_Verify(t *testing.T) {
	v := NewAPIKeyVerifier("my-secret-key")
	if _, err := v.Verify("wrong-key"); err == nil {
		t.Fatal("expected error for wrong key")
	}
	p, err := v.Verify("my-secret-key")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !p.APIKey || p.Role != RoleService {
		t.Fatalf("expected APIKey=true Role=service, got %+v", p)
	}
}

func TestMultiVerifier_FirstWins(t *testing.T) {
	multi := NewMultiVerifier(
		NewAPIKeyVerifier("api-key-1"),
		NewJWTVerifier("jwt-secret-32-bytes-minimum-length!", "fraud-test"),
	)

	// API key works.
	p, err := multi.Verify("api-key-1")
	if err != nil {
		t.Fatalf("api key verify: %v", err)
	}
	if !p.APIKey {
		t.Fatal("expected APIKey principal")
	}

	// JWT works.
	issuer := NewIssuer("jwt-secret-32-bytes-minimum-length!", "fraud-test")
	token, _ := issuer.IssueToken(Principal{ID: "u1", Role: RoleAdmin}, time.Hour)
	p, err = multi.Verify(token)
	if err != nil {
		t.Fatalf("jwt verify: %v", err)
	}
	if p.APIKey {
		t.Fatal("expected JWT principal, not APIKey")
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc", ""}, // case-sensitive prefix
		{"", ""},
		{"Basic xyz", ""},
	}
	for _, c := range cases {
		if got := ExtractBearer(c.in); got != c.out {
			t.Errorf("ExtractBearer(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}
