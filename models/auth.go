package models

import (
	"time"

	"github.com/dhickie/hickhub-api/models/enums"
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
	Scopes             []enums.Scope
	Type               enums.TokenType
}

// Client represents an OAuth client
type Client struct {
	ID           string
	Secret       string
	Type         enums.ClientType
	RedirectURIs []string
}

// Authorisation represents authorisation given by a user for a particular client, scope and redirect URL
type Authorisation struct {
	UserID      string
	Expiry      time.Time
	Scopes      []enums.Scope
	ClientID    string
	RedirectURL string
}
