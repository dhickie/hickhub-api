package models

import (
	"time"
)

// Scopes define what actions and data are available to an authorised client application
const (
	ScopeMessaging = "messaging" // Provides access to messaging between cloud and HickHub
	ScopeUser      = "user"      // Provides access to user information
	ScopeAdmin     = "admin"     // Provides access to EVERYTHING
)

// Client types identify what sort of client is trying to authenticate
const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"
)

// Grant types identify the type of auth grant being requested
const (
	GrantTypeAuthCode          = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
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
	Type         string
	RedirectURIs []string
}

// Authorisation represents authorisation given by a user for a particular client, scope and redirect URL
type Authorisation struct {
	UserID      string
	Expiry      time.Time
	Scope       string
	ClientID    string
	RedirectURL string
}
