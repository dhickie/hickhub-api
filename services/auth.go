package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dhickie/hickhub-api/models"

	"golang.org/x/crypto/bcrypt"
)

// AuthService provides methods for validation passwords and auth tokens
type AuthService struct {
	userIDMap        map[string]string
	passHashMap      map[string]string
	clientURIMap     map[string][]string
	authCodeLifetime int
	authCodeHashKey  string
}

// NewAuthService returns a new auth service using the provided config
func NewAuthService(config models.Config) *AuthService {
	return &AuthService{
		userIDMap:        make(map[string]string),
		passHashMap:      make(map[string]string),
		clientURIMap:     make(map[string][]string),
		authCodeLifetime: config.AuthCodeLifetime,
		authCodeHashKey:  config.AuthCodeHashKey,
	}
}

// ValidateClient validates the client details of the auth request
func (s *AuthService) ValidateClient(clientID, redirectURI string) (bool, error) {
	// Get the valid redirect URIs for this client
	validURIs, err := s.getClientRedirectURIs(clientID)
	if err != nil {
		return false, err
	}

	// If the redirectURI isn't included in the valid ones, then this isn't valid
	for _, v := range validURIs {
		if strings.EqualFold(v, redirectURI) {
			return true, nil
		}
	}
	return false, nil
}

// ValidatePassword validates that the give email/password combination is correct
func (s *AuthService) ValidatePassword(email, password string) (bool, error) {
	// Get the user ID
	userID, err := s.getUserID(email)
	if err != nil {
		return false, err
	}

	// Get the password hash for the user
	passHash, err := s.getPassHash(userID)
	if err != nil {
		return false, err
	}

	// Validate the provided password against the hash
	if err = bcrypt.CompareHashAndPassword([]byte(passHash), []byte(password)); err != nil {
		// Invalid password
		return false, nil
	}

	// Valid password
	return true, nil
}

// GenerateAuthCode generates a new auth code for the given email address and scope
func (s *AuthService) GenerateAuthCode(email, scope string) (string, error) {
	// Get the user's ID
	userID, err := s.getUserID(email)
	if err != nil {
		return "", err
	}

	// Generate an auth code encoding the user ID and time of expiry
	expiry := time.Now().Add(time.Duration(s.authCodeLifetime) * time.Second)
	unencrypted := fmt.Sprintf("%v_%v_%v", expiry.Format("20060102150405000"), userID, scope)
	return s.encryptCode(unencrypted)
}

func (s *AuthService) getClientRedirectURIs(clientID string) ([]string, error) {
	// Check the cache first
	if val, ok := s.clientURIMap[clientID]; ok {
		return val, nil
	}

	// Go to the database
	// TODO: Database magic
	var redirectURIs []string

	// Put the returned values in the cache
	s.clientURIMap[clientID] = redirectURIs
	return redirectURIs, nil
}

func (s *AuthService) getUserID(email string) (string, error) {
	// Check the cache first
	if val, ok := s.userIDMap[email]; ok {
		return val, nil
	}

	// Go to the database
	// TODO: Database magic
	var userID string

	// Put the returned value in the cache
	s.userIDMap[email] = userID
	return userID, nil
}

func (s *AuthService) getPassHash(userID string) (string, error) {
	// Check the cache first
	if val, ok := s.passHashMap[userID]; ok {
		return val, nil
	}

	// Go to the database
	// TODO: Database magic
	var passHash string

	// Put the returned value in the cache
	s.passHashMap[userID] = passHash
	return passHash, nil
}

func (s *AuthService) encryptCode(authCode string) (string, error) {
	gcm, err := s.getGCM()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	return string(gcm.Seal(nonce, nonce, []byte(authCode), nil)), nil
}

func (s *AuthService) decryptCode(encryptedCode string) (string, error) {
	gcm, err := s.getGCM()
	if err != nil {
		return "", err
	}

	bytes := []byte(encryptedCode)
	nonceSize := gcm.NonceSize()
	if len(bytes) < nonceSize {
		return "", errors.New("encrypted code is too short")
	}

	nonce, bytes := bytes[:nonceSize], bytes[nonceSize:]
	decryptedCode, err := gcm.Open(nil, nonce, bytes, nil)
	return string(decryptedCode), err
}

func (s *AuthService) getGCM() (cipher.AEAD, error) {
	c, err := aes.NewCipher([]byte(s.authCodeHashKey))
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(c)
}
