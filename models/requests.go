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

// ChangeEmailRequest is sent in the body of requests to change a user's email address
type ChangeEmailRequest struct {
	NewEmail string `json:"new_email"`
}

// ChangePasswordRequest is sent in the body of requests to change a user's password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}
