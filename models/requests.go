package models

// AuthoriseRequest is sent in the body of requests to the Authorise endpoint
type AuthoriseRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	RedirectURI string `json:"redirect_uri"`
}

// TokenRequest is received in a form by the Token endpoint
type TokenRequest struct {
	GrantType         string `schema:"grant_type"`
	ClientID          string `schema:"client_id"`
	ClientSecret      string `schema:"client_secret"`
	RedirectURI       string `schema:"redirect_uri"`
	AuthorisationCode string `schema:"code"`
	RefreshToken      string `schema:"refresh_token"`
	Scope             string `schema:"scope"`
}

// NewUserRequest is sent in the body of requests to register a new user
type NewUserRequest struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	SecurityQuestion string `json:"security_question"`
	SecurityAnswer   string `json:"security_answer"`
}
