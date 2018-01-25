package models

// Config represents the config of the API
type Config struct {
	AuthCodeLifetime     int    `json:"auth_code_lifetime"`
	AccessTokenLifetime  int    `json:"access_token_lifetime"`
	RefreshTokenLifetime int    `json:"refresh_token_lifetime"`
	AuthCodeHashKey      string `json:"auth_code_hash_key"`
}
