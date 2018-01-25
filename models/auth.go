package models

import (
	"time"
)

// AccessTokenPair represents a pair of access tokens used to authenticate with the API
type AccessTokenPair struct {
	ID                 string
	AccessToken        string
	RefreshToken       string
	AccessTokenExpiry  time.Time
	RefreshTokenExpiry time.Time
	UserID             string
	Scope              string
}
