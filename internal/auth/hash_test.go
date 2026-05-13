package auth

import (
	"strings"
	"testing"
)

// TestHashPassword verifies that HashPassword returns a valid SSHA512 hash
func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)

	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hash, "{SSHA512}") {
		t.Errorf("hash should start with {SSHA512}, got: %s", hash)
	}

	if len(hash) <= len("{SSHA512}") {
		t.Errorf("hash should contain encoded data, got: %s", hash)
	}
}

// TestVerifyPassword verifies round-trip: hash then verify returns true
func TestVerifyPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !VerifyPassword(password, hash) {
		t.Errorf("VerifyPassword should return true for correct password")
	}
}

// TestVerifyPasswordWrong verifies that wrong password returns false
func TestVerifyPasswordWrong(t *testing.T) {
	password := "testpassword123"
	wrongPassword := "wrongpassword456"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if VerifyPassword(wrongPassword, hash) {
		t.Errorf("VerifyPassword should return false for wrong password")
	}
}

// TestHashPasswordEmpty verifies that empty password returns error
func TestHashPasswordEmpty(t *testing.T) {
	hash, err := HashPassword("")

	if err == nil {
		t.Errorf("HashPassword should return error for empty password")
	}

	if hash != "" {
		t.Errorf("HashPassword should return empty string on error, got: %s", hash)
	}
}

// TestHashPasswordRandomSalt verifies that two calls produce different hashes
func TestHashPasswordRandomSalt(t *testing.T) {
	password := "testpassword123"

	hash1, err1 := HashPassword(password)
	if err1 != nil {
		t.Fatalf("First HashPassword failed: %v", err1)
	}

	hash2, err2 := HashPassword(password)
	if err2 != nil {
		t.Fatalf("Second HashPassword failed: %v", err2)
	}

	if hash1 == hash2 {
		t.Errorf("Two calls with same password should produce different hashes due to random salt")
	}

	// Both should still verify correctly
	if !VerifyPassword(password, hash1) {
		t.Errorf("First hash should verify correctly")
	}
	if !VerifyPassword(password, hash2) {
		t.Errorf("Second hash should verify correctly")
	}
}

func TestHashSSHA512RoundTrip(t *testing.T) {
	t.Parallel()

	hash, err := HashSSHA512("roundtrip-password")
	if err != nil {
		t.Fatalf("HashSSHA512() error = %v", err)
	}

	if !VerifyPassword("roundtrip-password", hash) {
		t.Fatal("VerifyPassword() = false, want true")
	}
}
