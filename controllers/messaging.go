package controllers

import (
	"net/http"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/services"
	"github.com/dhickie/hickhub-api/utils"
)

// MessagingController handles requests to do with sending messages to user's HickHubs
type MessagingController struct {
	messagingService services.MessagingService
	usersDAL         dal.UsersDAL
}

// NewMessagingController returns a new instance of the messaging controller
func NewMessagingController(dal dal.UsersDAL, messagingService services.MessagingService) MessagingController {
	return MessagingController{
		messagingService: messagingService,
		usersDAL:         dal,
	}
}

// Request makes a request to the NATS server, and returns the response
func (c *MessagingController) Request(w http.ResponseWriter, userID string, body []byte) {
	// Get the user object
	user, err := c.usersDAL.GetUserByID(userID)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	// Since this is a pass-through, we can pass send the body as the request
	reply, err := c.messagingService.Request(user.MessagingSubject, body, 10000)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	_, err = w.Write(reply)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
}
