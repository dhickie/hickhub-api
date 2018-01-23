package models

// AuthoriseResponse is sent in response to successful Authorise requests
type AuthoriseResponse struct {
	AuthorisationCode string `json:"authorisation_code"`
}
