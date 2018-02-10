package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"

	"golang.org/x/crypto/bcrypt"
)

// AuthService provides methods for validation passwords and auth tokens
type AuthService interface {
	ValidateClientRedirect(clientID, redirectURI string) (bool, error)
	ValidateClientCredentials(clientID, clientSecret, grantType string) (bool, error)
	ValidatePassword(email, password string) (bool, error)
	GenerateAuthCode(email, scope, clientID, redirectURI string) (*string, error)
	ValidateAuthCode(code, clientID, redirectURI string) (*models.Authorisation, error)
	ValidateRefreshToken(refreshToken string) (bool, error)
	GenerateAccessTokenPair(userID, scope string) (*models.AccessTokenPair, error)
	RefreshAccessTokenPair(refreshToken string) (*models.AccessTokenPair, error)
	GetAccessTokenLifetime() int
}

// HickHubAuthService is the HickHub implementation of the AuthService interface
type HickHubAuthService struct {
	authDAL              dal.OAuthDAL
	userDAL              dal.UsersDAL
	clientDAL            dal.ClientsDAL
	authCodeLifetime     int
	AccessTokenLifetime  int
	RefreshTokenLifetime int
	authCodeHashKey      string
}

// MustHickHubAuthService either returns a valid auth service or panics on error
func MustHickHubAuthService(config *models.Config, authDAL dal.OAuthDAL, userDAL dal.UsersDAL, clientDAL dal.ClientsDAL) AuthService {
	s, err := NewHickHubAuthService(config, authDAL, userDAL, clientDAL)
	if err != nil {
		panic(err)
	}

	return s
}

// NewHickHubAuthService returns a new auth service using the provided config
func NewHickHubAuthService(config *models.Config, authDAL dal.OAuthDAL, userDAL dal.UsersDAL, clientDAL dal.ClientsDAL) (AuthService, error) {
	return &HickHubAuthService{
		authDAL:              authDAL,
		userDAL:              userDAL,
		clientDAL:            clientDAL,
		authCodeLifetime:     config.AuthCodeLifetime,
		AccessTokenLifetime:  config.AccessTokenLifetime,
		RefreshTokenLifetime: config.RefreshTokenLifetime,
		authCodeHashKey:      config.AuthCodeHashKey,
	}, nil
}

const dateFormat = "20060102150405000"

// ValidateClientRedirect validates the client details of the auth request
func (s *HickHubAuthService) ValidateClientRedirect(clientID, redirectURI string) (bool, error) {
	// Get the valid redirect URIs for this client
	client, err := s.clientDAL.GetClientByID(clientID)
	if err != nil {
		return false, err
	}

	// If the redirectURI isn't included in the valid ones, then this isn't valid
	for _, v := range client.RedirectURIs {
		if strings.EqualFold(v, redirectURI) {
			return true, nil
		}
	}
	return false, nil
}

// ValidateClientCredentials validates provided client credentials against values from the database
func (s *HickHubAuthService) ValidateClientCredentials(clientID, clientSecret, grantType string) (bool, error) {
	// Get the actual client secret for this client
	client, err := s.clientDAL.GetClientByID(clientID)
	if err != nil {
		return false, err
	}

	// Return false if the secrets aren't the same
	if client.Secret != clientSecret {
		return false, nil
	}

	// Check that this client can request this type of grant
	if client.Type == models.ClientTypePublic && grantType == models.GrantTypeClientCredentials {
		// Only confidential clients may request the client credentials grant
		return false, nil
	}

	return true, nil
}

// ValidatePassword validates that the give email/password combination is correct
func (s *HickHubAuthService) ValidatePassword(email, password string) (bool, error) {
	// Get the user ID
	user, err := s.userDAL.GetUserByEmail(email)
	if err != nil {
		return false, err
	}

	// If the user doesn't exist, return false with no error
	if user == nil {
		return false, nil
	}

	// Validate the provided password against the hash
	if err = bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		// Invalid password
		return false, nil
	}

	// Valid password
	return true, nil
}

// GenerateAuthCode generates a new auth code for the given email address and scope
func (s *HickHubAuthService) GenerateAuthCode(email, scope, clientID, redirectURI string) (*string, error) {
	// Get the user's ID
	user, err := s.userDAL.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	// Generate an auth code encoding the user ID and time of expiry
	expiry := time.Now().Add(time.Duration(s.authCodeLifetime) * time.Second)
	unencrypted := fmt.Sprintf("%v_%v_%v_%v_%v", expiry.Format(dateFormat), user.ID, scope, clientID, redirectURI)
	return s.encryptCode(unencrypted)
}

// ValidateAuthCode validates the provided code against the provided client ID and redirect URI. If valid,
// it returns the decoded authorisation. Otherwise, it returns nil
func (s *HickHubAuthService) ValidateAuthCode(code, clientID, redirectURI string) (*models.Authorisation, error) {
	// Decrypt the code
	decrypted, err := s.decryptCode(code)
	if err != nil || decrypted == nil {
		return nil, err
	}

	// Split the code in to its individual components, and ensure it's still valid for this client ID and redirect URI
	components := strings.Split(*decrypted, "_")
	if len(components) != 5 {
		return nil, nil
	}

	// Expiry - if an error is returned then chances are it's because it's malformed - just return nil
	expiry, err := time.Parse(dateFormat, components[0])
	if err != nil {
		return nil, nil
	}
	if expiry.Before(time.Now()) {
		return nil, nil
	}

	// Client ID
	codeClientID := components[3]
	if codeClientID != clientID {
		return nil, nil
	}

	// Redirect URL
	codeRedirectURI := components[4]
	if codeRedirectURI != redirectURI {
		return nil, nil
	}

	// All good, return the authorisation
	return &models.Authorisation{
		UserID:      components[1],
		Expiry:      expiry,
		Scope:       components[2],
		ClientID:    codeClientID,
		RedirectURL: components[4],
	}, nil
}

// ValidateRefreshToken validates that the provided refresh token is valid
func (s *HickHubAuthService) ValidateRefreshToken(refreshToken string) (bool, error) {
	// Get the access token pair from storage
	tokenPair, err := s.authDAL.GetAccessTokenPairByRefreshToken(refreshToken)
	if err != nil {
		return false, err
	}
	if tokenPair == nil {
		return false, nil
	}

	// Validate that the refresh token hasn't expired
	if tokenPair.RefreshTokenExpiry.Before(time.Now()) {
		return false, nil
	}

	return true, nil
}

// GenerateAccessTokenPair generates an access token and refresh token for the given user ID and scope
// and stores it to the database
func (s *HickHubAuthService) GenerateAccessTokenPair(userID, scope string) (*models.AccessTokenPair, error) {
	// Generate two random tokens
	accessToken, err := utils.Crypto.GenerateRandomToken(32)
	if err != nil {
		return nil, err
	}
	refreshToken, err := utils.Crypto.GenerateRandomToken(32)
	if err != nil {
		return nil, err
	}

	// Determine the expiry of the new tokens
	start := time.Now()
	accessExpiry := start.Add(time.Duration(s.AccessTokenLifetime) * time.Second)
	refreshExpiry := start.Add(time.Duration(s.RefreshTokenLifetime) * time.Second)

	// Store the new tokens in the database
	result := &models.AccessTokenPair{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		AccessTokenExpiry:  accessExpiry,
		RefreshTokenExpiry: refreshExpiry,
		UserID:             userID,
		Scope:              scope,
	}

	err = s.authDAL.InsertAccessTokenPair(result)
	return result, err
}

// RefreshAccessTokenPair refreshes the token pair with the provided refresh token
func (s *HickHubAuthService) RefreshAccessTokenPair(refreshToken string) (*models.AccessTokenPair, error) {
	// Get the current token pair
	tokenPair, err := s.authDAL.GetAccessTokenPairByRefreshToken(refreshToken)
	if err != nil || tokenPair == nil {
		return nil, err
	}

	// Generate the new access tokens
	newPair, err := s.GenerateAccessTokenPair(tokenPair.UserID, tokenPair.Scope)
	if err != nil || newPair == nil {
		return nil, err
	}

	// Delete the old tokens from the database
	if err = s.authDAL.DeleteAccessTokenPair(tokenPair); err != nil {
		return nil, err
	}

	return newPair, nil
}

// GetAccessTokenLifetime returns the lifetime of an access token issued by this service
func (s *HickHubAuthService) GetAccessTokenLifetime() int {
	return s.AccessTokenLifetime
}

func (s *HickHubAuthService) encryptCode(authCode string) (*string, error) {
	gcm, err := s.getGCM()
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := base64.URLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(authCode), nil))
	return &encrypted, nil
}

func (s *HickHubAuthService) decryptCode(encryptedCode string) (*string, error) {
	gcm, err := s.getGCM()
	if err != nil {
		return nil, err
	}

	bytes, err := base64.URLEncoding.DecodeString(encryptedCode)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(bytes) < nonceSize {
		return nil, nil
	}

	nonce, bytes := bytes[:nonceSize], bytes[nonceSize:]
	decryptedCode, err := gcm.Open(nil, nonce, bytes, nil)
	if err != nil {
		return nil, err
	}

	decryptedString := string(decryptedCode)
	return &decryptedString, err
}

func (s *HickHubAuthService) getGCM() (cipher.AEAD, error) {
	c, err := aes.NewCipher([]byte(s.authCodeHashKey))
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(c)
}
