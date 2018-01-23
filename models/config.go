package models

// Config represents the config of the API
type Config struct {
	AuthCodeLifetime int    `json:"auth_code_lifetime"`
	AuthCodeHashKey  string `json:"auth_code_hash_key"`
}
