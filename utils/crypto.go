package utils

import (
	"crypto/rand"
	"encoding/base64"
)

// Crypto provides access to cryptographic utility functions
var Crypto = cryptoUtil{}

type cryptoUtil struct{}

// GenerateRandomToken generates a random token using a byte array of the provided length
func (u *cryptoUtil) GenerateRandomToken(length int) (string, error) {
	// Get a random byte array
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Encode it as URL encoded base 64 string
	return base64.URLEncoding.EncodeToString(bytes), nil
}
