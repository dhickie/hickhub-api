package services

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
	nats "github.com/nats-io/go-nats"
)

/*
 *	Messages sent on {UserSubject}
 *	Replies received on {NodeID}.{UserSubject}.reply
 *
 *	Server subscribes to {NodeID}.*.reply
 *	Users have permission to publish to *.{UserSubject}.reply
 */

// ErrReplyTimeout is returned if there is no reply recieved to a request within the specified timeout
var ErrReplyTimeout = errors.New("The reply from the request recipient timed out")

// MessagingService provides a method for publishing messages to user's HickHubs
type MessagingService interface {
	Request(userSubject string, request []byte, timeout int) ([]byte, error)
}

// NatsMessagingService fulfils the MessagingService interface using NATS
type NatsMessagingService struct {
	nodeID     string
	nc         *nats.Conn
	replySub   *nats.Subscription
	replyChans map[string]map[int64]chan []byte
	messageIDs map[string]*int64
	mapLock    sync.Mutex
}

// MustNatsMessagingService either returns a nats messaging service using the given config, or panics on error
func MustNatsMessagingService(config *models.Config) MessagingService {
	s, err := NewNatsMessagingService(config)
	if err != nil {
		panic(err)
	}

	return s
}

// NewNatsMessagingService creates a new NATS messaging service using the provided API config
func NewNatsMessagingService(config *models.Config) (MessagingService, error) {
	// Connect to the NATS instance
	adminKey := config.NatsAdminKey
	nc, err := nats.Connect(config.NatsConnectionString, nats.Token(adminKey))
	if err != nil {
		return nil, err
	}

	// Assign this API node a unique identifier
	nodeID, err := utils.Crypto.GenerateRandomToken(16)
	if err != nil {
		return nil, err
	}

	service := new(NatsMessagingService)
	service.nodeID = nodeID
	service.nc = nc
	service.replyChans = make(map[string]map[int64]chan []byte)
	service.messageIDs = make(map[string]*int64)

	// Create a wildcard subscription to receive all replies to requests
	replySubject := nodeID + ".*.reply"
	replySub, err := nc.Subscribe(replySubject, service.replyHandler)
	if err != nil {
		return nil, err
	}

	service.replySub = replySub
	return service, nil
}

// Request sends the specified message to the specifier user subject, with the specified timeout in milliseconds
func (s *NatsMessagingService) Request(userSubject string, message []byte, timeout int) ([]byte, error) {
	// See whether we've sent a message to this user in the past
	var userChannelMap map[int64]chan []byte
	var messageID *int64
	var found bool
	if userChannelMap, found = s.replyChans[userSubject]; !found {
		s.mapLock.Lock()
		if userChannelMap, found = s.replyChans[userSubject]; !found {
			userChannelMap = make(map[int64]chan []byte)
			messageID = new(int64)

			s.replyChans[userSubject] = userChannelMap
			s.messageIDs[userSubject] = messageID
		}
		s.mapLock.Unlock()
	}

	if found {
		messageID = s.messageIDs[userSubject]
	}

	// Now we've got the user's map of reply channels, increment the message ID, create a reply channel,
	// and send the request
	newMessageID := atomic.AddInt64(messageID, 1)
	replyChannel := make(chan []byte)
	userChannelMap[newMessageID] = replyChannel

	// Remove the channel from the map when we leave the method (success or failure)
	defer delete(userChannelMap, newMessageID)

	natsMsg := models.HickHubMessage{
		ID:   newMessageID,
		Data: message,
	}
	replySubject := s.nodeID + "." + userSubject + ".reply"
	marshaledMessage, err := json.Marshal(natsMsg)
	if err != nil {
		return nil, err
	}

	err = s.nc.PublishRequest(userSubject, replySubject, marshaledMessage)
	if err != nil {
		return nil, err
	}

	// Recieve the reply on the reply channel (or timeout)
	ticker := time.NewTicker(time.Duration(timeout) * time.Millisecond)
	select {
	case <-ticker.C:
		// Timeout, delete the reply channel from the map and return an error
		return nil, ErrReplyTimeout
	case reply := <-replyChannel:
		// Return the reply
		return reply, nil
	}
}

func (s *NatsMessagingService) replyHandler(msg *nats.Msg) {
	// Try to get the reply channel for this user's subject and message ID
	subjectComponents := strings.Split(msg.Subject, ".")
	if len(subjectComponents) == 3 {
		userSubject := subjectComponents[1]
		if channels, ok := s.replyChans[userSubject]; ok {
			hhMsg := new(models.HickHubMessage)
			err := json.Unmarshal(msg.Data, hhMsg)
			if err != nil {
				// Bad message, ignore
				return
			}

			if channel, ok := channels[hhMsg.ID]; ok {
				// Huzzah, good message, send the reply to the channel (or timeout)
				ticker := time.NewTicker(1000 * time.Millisecond)
				select {
				case <-ticker.C:
					// Timeout, ignore
				case channel <- hhMsg.Data:
					// Successfully sent the reply
				}

			}
		}
	}

	// Bad message, ignore
}
