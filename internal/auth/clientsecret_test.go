package auth

import (
	"encoding/hex"
	"regexp"
	"testing"
)

func TestDeriveOAuthClientSecret(t *testing.T) {
	t.Parallel()

	const jwtSecret = "0123456789abcdef0123456789abcdef"
	got := DeriveOAuthClientSecret(jwtSecret)

	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got) {
		t.Fatalf("secret = %q, want 64 lowercase hex chars", got)
	}
	if again := DeriveOAuthClientSecret(jwtSecret); again != got {
		t.Fatalf("not deterministic: %q != %q", again, got)
	}
	if other := DeriveOAuthClientSecret("fedcba9876543210fedcba9876543210"); other == got {
		t.Fatal("different JWT secrets derived the same client secret")
	}
	if cookieKey := hex.EncodeToString(deriveKey([]byte(jwtSecret), stateKeyLabel)); cookieKey == got {
		t.Fatal("client secret equals the state-cookie MAC key")
	}
}
