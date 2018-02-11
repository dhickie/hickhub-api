package utils

import (
	"regexp"
)

type validationUtil struct{}

// Validation provides access to validation helper methods
var Validation = validationUtil{}

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// ValidateEmail checks whether an email address has a valid format. Returns true if valid
func (u *validationUtil) ValidateEmail(email string) bool {
	return emailRegex.MatchString(email)
}
