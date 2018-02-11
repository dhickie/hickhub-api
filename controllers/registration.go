package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/dhickie/hickhub-api/services"

	"golang.org/x/crypto/bcrypt"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
)

const (
	emailAddressTaken = "Email address is taken"
	noEmailProvided   = "No email address provided to check availability"
)

// RegistrationController handles requests to do with new user registration
type RegistrationController struct {
	usersDAL    dal.UsersDAL
	authService services.AuthService
}

// NewRegistrationController returns a new Registration controller using the provided services
func NewRegistrationController(usersDAL dal.UsersDAL, authService services.AuthService) *RegistrationController {
	return &RegistrationController{
		usersDAL:    usersDAL,
		authService: authService,
	}
}

// RegisterNewUser registers a new user and adds their details to the database. It also generates their API
// token and an initial access token pair for immediate access.
func (c *RegistrationController) RegisterNewUser(w http.ResponseWriter, vars map[string]string, body []byte) {
	// Unmarshal the body
	request := new(models.NewUserRequest)
	if err := json.Unmarshal(body, request); err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Check that this user doesn't already exist
	existingUser, err := c.usersDAL.GetUserByEmail(request.Email)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if existingUser != nil {
		utils.HTTP.RespondBadRequest(w, emailAddressTaken)
		return
	}

	// Hash the password
	passHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Generate a random messaging subject
	subject, err := utils.Crypto.GenerateRandomToken(32)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Add the user to the database
	user := &models.User{
		Email:            request.Email,
		PassHash:         string(passHash),
		MessagingSubject: subject,
		SecurityQuestion: request.SecurityQuestion,
		SecurityAnswer:   request.SecurityAnswer,
	}
	if err = c.usersDAL.InsertUser(user); err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Generate an API token for the user
	if _, err = c.authService.GenerateAPIToken(user.ID); err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Generate an access token pair for immediate usage
	tokenPair, err := c.authService.GenerateAccessTokenPair(user.ID, "user;messaging")
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	response := models.NewUserResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}
	utils.HTTP.RespondOK(w, response)
}

// GetEmailAvailability checks whether an email address is available for use by a new user
func (c *RegistrationController) GetEmailAvailability(w http.ResponseWriter, vars map[string]string, body []byte) {
	// Get the email we want to check for
	email, ok := vars["email"]
	if !ok {
		utils.HTTP.RespondBadRequest(w, noEmailProvided)
		return
	}

	// Try to get a user by this email
	user, err := c.usersDAL.GetUserByEmail(email)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Return a result based on whether we found a user or not
	result := models.EmailAvailabilityResponse{}
	if user == nil {
		result.EmailAvailable = true
	}

	utils.HTTP.RespondOK(w, result)
}
