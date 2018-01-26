package controllers

import (
	"net/http"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/services"
	"github.com/dhickie/hickhub-api/utils"
)

// AuthController handles requests to do with user authentication
type AuthController struct {
	authService *services.AuthService
}

// NewAuthController returns a new auth controller using the given auth service
func NewAuthController(authService *services.AuthService) AuthController {
	return AuthController{
		authService: authService,
	}
}

// Authorise validates a user's email and password, and returns a short lived auth code if they are valid
func (c *AuthController) Authorise(w http.ResponseWriter, r *http.Request) {
	clientID, scope, redirectURI := c.getAuthParams(r)
	body := new(models.AuthoriseRequest)
	if err := utils.HTTP.ReadRequestBody(r, body); err != nil {
		utils.HTTP.RespondBadRequest(w, err.Error())
		return
	}

	// Validate the client ID and redirect URI
	valid, err := c.authService.ValidateClientRedirect(clientID, redirectURI)
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
	code, err := c.authService.GenerateAuthCode(body.Email, scope, clientID, redirectURI)
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
	grantType, clientID, clientSecret, redirectURL, codeOrToken, err := c.getTokenFormValues(r)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Validate the client credentials
	valid, err := c.authService.ValidateClientCredentials(clientID, clientSecret)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if !valid {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	// Check whether this is refreshing an existing access token, or exchanging an authorisation code
	if grantType == "authorization_code" {
		c.authCodeToken(w, codeOrToken, clientID, redirectURL)
		return
	} else if grantType == "refresh_token" {
		c.refreshTokenToken(w, codeOrToken)
		return
	}

	utils.HTTP.RespondBadRequest(w, "Invalid grant type")
	return
}

func (c *AuthController) authCodeToken(w http.ResponseWriter, code, clientID, redirectURL string) {
	// Validate the provided code
	authorisation, err := c.authService.ValidateAuthCode(code, clientID, redirectURL)
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
		ExpiresIn:    c.authService.AccessTokenLifetime,
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
		ExpiresIn:    c.authService.AccessTokenLifetime,
		Scope:        tokenPair.Scope,
		TokenType:    "bearer",
	}

	utils.HTTP.RespondOK(w, response)
	return
}

func (c *AuthController) getAuthParams(r *http.Request) (string, string, string) {
	queryParams := r.URL.Query()
	clientID := queryParams.Get("client_id")
	scope := queryParams.Get("scope")
	redirectURI := queryParams.Get("redirect_uri")

	return clientID, scope, redirectURI
}

func (c *AuthController) getTokenFormValues(r *http.Request) (string, string, string, string, string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", "", "", "", "", err
	}

	grantType := r.Form.Get("grant_type")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	redirectURL := r.Form.Get("redirect_url")
	codeOrToken := ""

	if grantType == "authorization_code" {
		codeOrToken = r.Form.Get("code")
	} else {
		codeOrToken = r.Form.Get("refresh_token")
	}

	return grantType, clientID, clientSecret, redirectURL, codeOrToken, nil
}
