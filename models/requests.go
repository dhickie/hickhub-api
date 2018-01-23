package models

// AuthoriseRequest is sent in the body of requests to the Authorise endpoint
type AuthoriseRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
