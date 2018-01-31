package models

// HickHubMessage represents a message being sent to a user's HickHub
type HickHubMessage struct {
	ID   int64  `json:"id"`
	Data []byte `json:"data"`
}
