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
	valid, err := c.authService.ValidateClient(clientID, redirectURI)
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
	code, err := c.authService.GenerateAuthCode(body.Email, scope)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	response := models.AuthoriseResponse{
		AuthorisationCode: code,
	}

	utils.HTTP.RespondOK(w, response)
}

func (c *AuthController) getAuthParams(r *http.Request) (string, string, string) {
	queryParams := r.URL.Query()
	clientID := queryParams.Get("client_id")
	scope := queryParams.Get("scope")
	redirectURI := queryParams.Get("redirect_uri")

	return clientID, scope, redirectURI
}
