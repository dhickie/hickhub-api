package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/dhickie/hickhub-api/services"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
)

const (
	invalidEmailFormat = "Invalid email format"
	emailTaken         = "Email address is already taken"
	incorrectPassword  = "Incorrect password provided"
)

// UserController provides access to endpoints which provide information about a user
type UserController struct {
	usersDAL    dal.UsersDAL
	authService services.AuthService
}

// NewUserController creates a new user controller using the provided user DAL service
func NewUserController(usersDAL dal.UsersDAL, authService services.AuthService) *UserController {
	return &UserController{
		usersDAL:    usersDAL,
		authService: authService,
	}
}

// Subject returns the messaging subject name for the user
func (c *UserController) Subject(w http.ResponseWriter, userID string, body []byte) {
	// Get the user's object
	user, err := c.usersDAL.GetUserByID(userID)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	} else if user == nil {
		utils.HTTP.RespondNotFound(w)
		return
	}

	// Return the subscription
	response := models.SubjectResponse{
		Subject: user.MessagingSubject,
	}
	utils.HTTP.RespondOK(w, response)
}

// ChangeEmail updates a user's email to a new value
func (c *UserController) ChangeEmail(w http.ResponseWriter, userID string, body []byte) {
	// Get email the user wants to change to
	request := new(models.ChangeEmailRequest)
	if err := json.Unmarshal(body, request); err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Validate the new email is actually valid
	if !utils.Validation.ValidateEmail(request.NewEmail) {
		utils.HTTP.RespondBadRequest(w, invalidEmailFormat)
		return
	}

	// Check whether someone else already has this email address
	existingUser, err := c.usersDAL.GetUserByEmail(request.NewEmail)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if existingUser != nil {
		utils.HTTP.RespondBadRequest(w, emailTaken)
		return
	}

	// All good, update the email in the database
	err = c.usersDAL.UpdateEmail(userID, request.NewEmail)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
	}
}

// ChangePassword changes the password for the given user ID to a new value
func (c *UserController) ChangePassword(w http.ResponseWriter, userID string, body []byte) {
	// Unmarshal the request
	request := new(models.ChangePasswordRequest)
	if err := json.Unmarshal(body, request); err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Validate that the provided current password is correct
	valid, err := c.authService.ValidatePasswordByID(userID, request.CurrentPassword)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
	if !valid {
		utils.HTTP.RespondBadRequest(w, incorrectPassword)
		return
	}

	// Set the new password
	hash, err := c.authService.HashPassword(request.NewPassword)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	err = c.usersDAL.UpdatePassword(userID, hash)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
}
