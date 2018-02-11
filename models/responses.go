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

// SubjectResponse is returned to requests for a user's messaging subject
type SubjectResponse struct {
	Subject string `json:"subject"`
}

// NewUserResponse is returned after the successful creation of a new user
type NewUserResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// EmailAvailabilityResponse is returned when checking whether an email address is available
type EmailAvailabilityResponse struct {
	EmailAvailable bool `json:"email_available"`
}
