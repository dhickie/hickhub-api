package models

// AuthoriseRequest is sent in the body of requests to the Authorise endpoint
type AuthoriseRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	RedirectURI string `json:"redirect_uri"`
}
