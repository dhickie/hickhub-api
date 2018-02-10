package controllers

import (
	"net/http"

	"github.com/gorilla/schema"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/services"
	"github.com/dhickie/hickhub-api/utils"
)

// AuthController handles requests to do with user authentication
type AuthController struct {
	authService services.AuthService
}

// NewAuthController returns a new auth controller using the given auth service
func NewAuthController(authService services.AuthService) AuthController {
	return AuthController{
		authService: authService,
	}
}

// Authorise validates a user's email and password, and returns a short lived auth code if they are valid
func (c *AuthController) Authorise(w http.ResponseWriter, r *http.Request) {
	body := new(models.AuthoriseRequest)
	if err := utils.HTTP.ReadRequestBody(r, body); err != nil {
		utils.HTTP.RespondBadRequest(w, err.Error())
		return
	}

	// Validate the client ID and redirect URI
	valid, err := c.authService.ValidateClientRedirect(body.ClientID, body.RedirectURI)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	// Return forbidden if the client ID and/or redirect URI aren't valid
	if !valid {
		utils.HTTP.RespondForbidden(w)
		return
	}

	// Validate the email/password combination
	valid, err = c.authService.ValidatePassword(body.Email, body.Password)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Credentials were invalid, return unauthorized
	if !valid {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	// Credentials were valid, generate an auth code
	code, err := c.authService.GenerateAuthCode(body.Email, body.Scope, body.ClientID, body.RedirectURI)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	response := models.AuthoriseResponse{
		AuthorisationCode: *code,
	}

	utils.HTTP.RespondOK(w, response)
}

// Token will either exchange an authorization code for an access token & refresh token, or refresh an existing token
// using a refresh token
func (c *AuthController) Token(w http.ResponseWriter, r *http.Request) {
	// Ensure that the request has the correct body form (www-form-urlencoded)
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		utils.HTTP.RespondBadRequest(w, "Bad content type - should be application/x-www-form-urlencoded")
		return
	}

	// Get the form values
	request := new(models.TokenRequest)
	err := r.ParseForm()
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(request, r.PostForm)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
	}

	// Validate the client credentials
	valid, err := c.authService.ValidateClientCredentials(request.ClientID, request.ClientSecret, request.GrantType)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if !valid {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	// Check what sort of grant the request is for, and take appropriate action
	if request.GrantType == models.GrantTypeAuthCode {
		c.authCodeToken(w, request.AuthorisationCode, request.ClientID, request.RedirectURI)
		return
	} else if request.GrantType == models.GrantTypeRefreshToken {
		c.refreshTokenToken(w, request.RefreshToken)
		return
	} else if request.GrantType == models.GrantTypeClientCredentials {
		c.clientToken(w, request.Scope)
		return
	}

	utils.HTTP.RespondBadRequest(w, "Invalid grant type")
	return
}

func (c *AuthController) authCodeToken(w http.ResponseWriter, code, clientID, redirectURI string) {
	// Validate the provided code
	authorisation, err := c.authService.ValidateAuthCode(code, clientID, redirectURI)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if authorisation == nil {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	// The code's valid, generate access and refresh tokens for the client
	tokenPair, err := c.authService.GenerateAccessTokenPair(authorisation.UserID, authorisation.Scope)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	response := models.TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    c.authService.GetAccessTokenLifetime(),
		Scope:        authorisation.Scope,
		TokenType:    "bearer",
	}

	utils.HTTP.RespondOK(w, response)
	return
}

func (c *AuthController) refreshTokenToken(w http.ResponseWriter, refreshToken string) {
	// Validate the provided refresh token
	valid, err := c.authService.ValidateRefreshToken(refreshToken)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if !valid {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	// The refresh token is valid, refresh it and the associated access token
	tokenPair, err := c.authService.RefreshAccessTokenPair(refreshToken)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	response := models.TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    c.authService.GetAccessTokenLifetime(),
		Scope:        tokenPair.Scope,
		TokenType:    "bearer",
	}

	utils.HTTP.RespondOK(w, response)
	return
}

func (c *AuthController) clientToken(w http.ResponseWriter, scope string) {
	// Generate a new token pair for an empty user ID, since this isn't a user authenticating
	tokenPair, err := c.authService.GenerateAccessTokenPair("", scope)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	response := models.TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    c.authService.GetAccessTokenLifetime(),
		Scope:        tokenPair.Scope,
		TokenType:    "bearer",
	}

	utils.HTTP.RespondOK(w, response)
	return
}
