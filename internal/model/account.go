package model

type Account struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Quota       int    `json:"quota"`
	Active      bool   `json:"active"`
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
}
