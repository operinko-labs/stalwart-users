package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

const ssha512Prefix = "{SSHA512}"

// HashPassword generates an SSHA512 hash of the password with a random 16-byte salt.
// Returns a string in the format: {SSHA512}<base64(sha512(password+salt)+salt)>
func HashPassword(password string) (string, error) {
	return HashSSHA512(password)
}

// HashSSHA512 generates an SSHA512 hash of the password with a random 16-byte salt.
// Returns a string in the format: {SSHA512}<base64(sha512(password+salt)+salt)>
func HashSSHA512(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Generate 16-byte random salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// Compute SHA512(password + salt)
	passwordBytes := []byte(password)
	hashInput := append(passwordBytes, salt...)
	hash := sha512.Sum512(hashInput)

	// Concatenate hash (64 bytes) + salt (16 bytes)
	hashAndSalt := append(hash[:], salt...)

	// Return {SSHA512} + base64(hash+salt)
	encoded := base64.StdEncoding.EncodeToString(hashAndSalt)
	return ssha512Prefix + encoded, nil
}

// VerifyPassword verifies a password against an SSHA512 hash.
// Returns true if the password matches, false otherwise.
func VerifyPassword(password, encoded string) bool {
	// Handle SSHA512 hashed passwords (case-insensitive prefix)
	if hasPrefix(encoded, ssha512Prefix) || hasPrefix(encoded, "{ssha512}") {
		return verifySsha512(password, encoded)
	}

	// Fallback: plaintext comparison (some Stalwart accounts use plaintext secrets)
	return subtle.ConstantTimeCompare([]byte(password), []byte(encoded)) == 1
}

func verifySsha512(password, encoded string) bool {
	// Strip prefix (handle both {SSHA512} and {ssha512})
	prefixLen := len(ssha512Prefix)

	// Base64 decode the remainder
	decoded, err := base64.StdEncoding.DecodeString(encoded[prefixLen:])
	if err != nil {
		return false
	}

	// Decoded should be at least 64 bytes (hash) + 16 bytes (salt) = 80 bytes
	if len(decoded) < 80 {
		return false
	}

	// Extract hash (first 64 bytes) and salt (remaining bytes)
	storedHash := decoded[:64]
	salt := decoded[64:]

	// Recompute: SHA512(password + salt)
	passwordBytes := []byte(password)
	hashInput := append(passwordBytes, salt...)
	computedHash := sha512.Sum512(hashInput)

	// Compare using constant-time comparison
	return subtle.ConstantTimeCompare(storedHash, computedHash[:]) == 1
}

// hasPrefix is a simple string prefix check
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
