package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
	userIDMap            map[string]string
	passHashMap          map[string]string
	clientURIMap         map[string][]string
	clientSecretMap      map[string]string
	authCodeLifetime     int
	AccessTokenLifetime  int
	RefreshTokenLifetime int
	authCodeHashKey      string
}

// NewAuthService returns a new auth service using the provided config
func NewAuthService(config models.Config) *AuthService {
	return &AuthService{
		userIDMap:            make(map[string]string),
		passHashMap:          make(map[string]string),
		clientURIMap:         make(map[string][]string),
		clientSecretMap:      make(map[string]string),
		authCodeLifetime:     config.AuthCodeLifetime,
		AccessTokenLifetime:  config.AccessTokenLifetime,
		RefreshTokenLifetime: config.RefreshTokenLifetime,
		authCodeHashKey:      config.AuthCodeHashKey,
	}
}

const dateFormat = "20060102150405000"

// ValidateClientRedirect validates the client details of the auth request
func (s *AuthService) ValidateClientRedirect(clientID, redirectURI string) (bool, error) {
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

// ValidateClientCredentials validates provided client credentials against values from the database
func (s *AuthService) ValidateClientCredentials(clientID, clientSecret string) (bool, error) {
	// Get the actual client secret for this client
	dbSecret, err := s.getClientSecret(clientID)
	if err != nil {
		return false, err
	}

	// Return false if the secrets aren't the same
	if dbSecret != clientSecret {
		return false, nil
	}

	return true, nil
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
func (s *AuthService) GenerateAuthCode(email, scope, clientID, redirectURI string) (string, error) {
	// Get the user's ID
	userID, err := s.getUserID(email)
	if err != nil {
		return "", err
	}

	// Generate an auth code encoding the user ID and time of expiry
	expiry := time.Now().Add(time.Duration(s.authCodeLifetime) * time.Second)
	unencrypted := fmt.Sprintf("%v_%v_%v_%v_%v", expiry.Format(dateFormat), userID, scope, clientID, redirectURI)
	return s.encryptCode(unencrypted)
}

// ValidateAuthCode validates the provided code against the provided client ID and redirect URI. If valid,
// it returns the user ID it was generated for, along with the scope it's valid for and a possible error.
// If the code isn't valid, it returns empty strings and a nil error
func (s *AuthService) ValidateAuthCode(code, clientID, redirectURI string) (string, string, error) {
	// Decrypt the code
	decrypted, err := s.decryptCode(code)
	if err != nil {
		return "", "", err
	}

	// Split the code in to its individual components, and ensure it's still valid for this client ID and redirect URI
	components := strings.Split(decrypted, "_")
	if len(components) != 5 {
		return "", "", nil
	}

	// Expiry
	expiry, err := time.Parse(dateFormat, components[0])
	if err != nil {
		return "", "", nil
	}
	if expiry.After(time.Now()) {
		return "", "", nil
	}

	// Client ID
	codeClientID := components[3]
	if codeClientID != clientID {
		return "", "", nil
	}

	// Redirect URI
	codeRedirectURI := components[4]
	if codeRedirectURI != redirectURI {
		return "", "", nil
	}

	// All good, return user ID and scope
	return components[1], components[2], nil
}

// ValidateRefreshToken validates that the provided refresh token is valid, and if it is returns
// the associated user ID and scope
func (s *AuthService) ValidateRefreshToken(refreshToken string) (string, string, error) {
	// Get the access token pair from storage
	tokenPair, err := s.getAccessTokenPair(refreshToken)
	if err != nil {
		return "", "", err
	}
	if tokenPair == nil {
		return "", "", nil
	}

	// Validate that the refresh token hasn't expired
	if tokenPair.RefreshTokenExpiry.After(time.Now()) {
		return "", "", nil
	}

	return tokenPair.UserID, tokenPair.Scope, nil
}

// GenerateAccessTokenPair generates an access token and refresh token for the given user ID and scope
// and stores it to the database
func (s *AuthService) GenerateAccessTokenPair(userID, scope string) (string, string, error) {
	// Generate two random tokens
	accessToken, err := s.generateRandomToken()
	if err != nil {
		return "", "", err
	}
	refreshToken, err := s.generateRandomToken()
	if err != nil {
		return "", "", err
	}

	// Determine the expiry of the new tokens
	start := time.Now()
	accessExpiry := start.Add(time.Duration(s.AccessTokenLifetime) * time.Second)
	refreshExpiry := start.Add(time.Duration(s.RefreshTokenLifetime) * time.Second)

	// Store the new tokens in the database/cache
	err = s.storeAccessTokenPair(accessToken, refreshToken, userID, scope, accessExpiry, refreshExpiry)
	return accessToken, refreshToken, err
}

// RefreshAccessTokenPair refreshes the token pair with the provided refresh token
func (s *AuthService) RefreshAccessTokenPair(refreshToken string) (string, string, error) {
	// Get the current token pair
	tokenPair, err := s.getAccessTokenPair(refreshToken)
	if err != nil {
		return "", "", err
	}

	// Generate the new access tokens
	accessToken, refreshToken, err := s.GenerateAccessTokenPair(tokenPair.UserID, tokenPair.Scope)
	if err != nil {
		return "", "", err
	}

	// Delete the old tokens from the database
	if err = s.deleteAccessTokenPair(tokenPair.ID); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
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

func (s *AuthService) getClientSecret(clientID string) (string, error) {
	// Check the cache first
	if val, ok := s.clientSecretMap[clientID]; ok {
		return val, nil
	}

	// Go to the database
	// TODO: Database magic
	var clientSecret string

	// Put the returned values in the cache
	s.clientSecretMap[clientID] = clientSecret
	return clientSecret, nil
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

func (s *AuthService) getAccessTokenPair(refreshToken string) (*models.AccessTokenPair, error) {
	// TODO: Database magic
	return &models.AccessTokenPair{}, nil
}

func (s *AuthService) storeAccessTokenPair(accessToken, refreshToken, userID, scope string, accessExpiry, refreshExpiry time.Time) error {
	// TODO: Database magic
	return nil
}

func (s *AuthService) deleteAccessTokenPair(ID string) error {
	// TODO: Database magic
	return nil
}

func (s *AuthService) generateRandomToken() (string, error) {
	// Get a random byte array
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Encode it as URL encoded base 64 string
	return base64.URLEncoding.EncodeToString(bytes), nil
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
