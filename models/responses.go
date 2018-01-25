package models

// AuthoriseResponse is sent in response to successful Authorise requests
type AuthoriseResponse struct {
	AuthorisationCode string `json:"authorisation_code"`
}

// TokenResponse is returned to successful calls to the Token auth endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}
