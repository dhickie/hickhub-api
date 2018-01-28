package controllers

import (
	"net/http"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/utils"

	"github.com/dhickie/hickhub-api/models"
	"github.com/nats-io/go-nats"
)

// MessagingController handles requests to do with sending messages to user's HickHubs
type MessagingController struct {
	natsConn *nats.Conn
	usersDAL *dal.UsersDAL
}

// NewMessagingController returns a new instance of the messaging controller
func NewMessagingController(config *models.Config, dal *dal.UsersDAL) MessagingController {
	// Create the connection to NATS
	adminKey := config.NatsAdminKey
	nc, err := nats.Connect(config.NatsConnectionString, nats.Token(adminKey))
	if err != nil {
		panic(err)
	}

	return MessagingController{
		natsConn: nc,
		usersDAL: dal,
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
	reply, err := c.natsConn.Request(user.MessagingSubject, body, 10000)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	_, err = w.Write(reply.Data)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}
}
