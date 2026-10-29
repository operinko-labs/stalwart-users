package auth

import "encoding/hex"

const clientSecretLabel = "stalwart-users oauth client secret"

// DeriveOAuthClientSecret returns the secret of stalwart-users' own OAuth
// client in Stalwart: hex(HMAC-SHA256(key=jwtSecret, msg=label)). It uses a
// different label from the state-cookie key, so the two never coincide.
func DeriveOAuthClientSecret(jwtSecret string) string {
	return hex.EncodeToString(deriveKey([]byte(jwtSecret), clientSecretLabel))
}
