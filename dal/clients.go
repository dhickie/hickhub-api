package dal

import (
	"database/sql"
	"strings"

	// Database driver for PostgreSQL
	_ "github.com/lib/pq"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
)

// ClientsDAL is a DAL component for accessing OAuth Client information
type ClientsDAL struct {
	db          *sql.DB
	clientCache map[string]*models.Client
}

// NewClientsDAL returns a new ClientsDAL service using the provided config
func NewClientsDAL(config *models.Config) (*ClientsDAL, error) {
	db, err := sql.Open("postgres", config.SQLConnectionString)
	if err != nil {
		return nil, err
	}

	return &ClientsDAL{
		db:          db,
		clientCache: make(map[string]*models.Client),
	}, nil
}

// GetClientByID returns a pointer to the client with the specified ID
func (dal *ClientsDAL) GetClientByID(ID string) (*models.Client, error) {
	// Check the cache
	if val, ok := dal.clientCache[ID]; ok {
		return val, nil
	}

	// Go to the database
	rows, err := dal.db.Query(Queries.GetClientByID, ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var id string
	var secret string
	var uris string
	found, err := utils.SQL.GetSingle(rows, &id, &secret, &uris)
	if !found || err != nil {
		return nil, err
	}

	result := new(models.Client)
	result.ID = id
	result.Secret = secret
	result.RedirectURIs = strings.Split(uris, ";")

	// Populate the cache
	dal.clientCache[ID] = result
	return result, nil
}
