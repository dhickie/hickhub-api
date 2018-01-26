package models

// User represents a user of the HickHub platform
type User struct {
	ID       string
	Email    string
	PassHash string
}
