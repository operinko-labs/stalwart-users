package model

type Account struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Quota       int    `json:"quota"`
	Active      bool   `json:"active"`
	// IsAdmin is only filled by ListAccounts, to hide full admins from domain
	// admins; it is never sent to clients.
	IsAdmin bool `json:"-"`
}

type CreateAccountRequest struct {
	Name        string `json:"name"`
	Password    string `json:"password"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
	Quota       int    `json:"quota,omitempty"`
}

type UpdateAccountRequest struct {
	Description *string `json:"description,omitempty"`
	Quota       *int    `json:"quota,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
	NewPassword     string `json:"new_password"`
	// OTPCode is the current two-factor code, needed for a self-service change
	// when the account has 2FA on.
	OTPCode string `json:"otp_code,omitempty"`
}
