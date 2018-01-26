package models

import (
	"time"
)

// Scopes define what actions and data are available to an authorised client application
const (
	ScopeMessaging = "messaging"
)

// AccessTokenPair represents a pair of access tokens used to authenticate with the API
type AccessTokenPair struct {
	ID                 string // Auto generated on insert
	AccessToken        string
	RefreshToken       string
	AccessTokenExpiry  time.Time
	RefreshTokenExpiry time.Time
	UserID             string
	Scope              string
}

// Client represents an OAuth client
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
}
