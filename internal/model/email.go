package model

type Email struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type"`
}

type CreateEmailRequest struct {
	Address string `json:"address"`
	Type    string `json:"type,omitempty"`
}
