package utils

import (
	"errors"
	"strings"

	"github.com/dhickie/hickhub-api/models/enums"
)

// ErrInvalidScope is returned if an invalid scope is provided to the split function
var ErrInvalidScope = errors.New("Invalid scope")

// Auth provides access to authentication related utility functions
var Auth = authUtil{}

type authUtil struct{}

// JoinScopes joins together the provided scopes in to a scope string
func (u *authUtil) JoinScopes(scopes []enums.Scope) string {
	scopeStrings := make([]string, 0)
	for _, v := range scopes {
		scopeStrings = append(scopeStrings, v.String())
	}

	return strings.Join(scopeStrings, ";")
}

// SplitScopes splits apart the provided scope string and returns the slice of scopes it represents
func (u *authUtil) SplitScopes(joinedScopes string) ([]enums.Scope, error) {
	scopes := make([]enums.Scope, 0)
	split := strings.Split(joinedScopes, ";")

	for _, v := range split {
		scope, valid := enums.ParseScope(v)
		if !valid {
			return nil, ErrInvalidScope
		}

		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// ContainsScope determines whether the provided slice of scopes contains the required scope
func (u *authUtil) ContainsScope(scopes []enums.Scope, requiredScope enums.Scope) bool {
	for _, v := range scopes {
		if v == requiredScope {
			return true
		}
	}

	return false
}
