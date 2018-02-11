package controllers

import (
	"net/http"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
)

// UserController provides access to endpoints which provide information about a user
type UserController struct {
	usersDAL dal.UsersDAL
}

// NewUserController creates a new user controller using the provided user DAL service
func NewUserController(usersDAL dal.UsersDAL) *UserController {
	return &UserController{
		usersDAL: usersDAL,
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
