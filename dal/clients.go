package dal

import (
	"database/sql"
	"strings"

	// Database driver for PostgreSQL
	_ "github.com/lib/pq"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/models/enums"
	"github.com/dhickie/hickhub-api/utils"
)

// ClientsDAL is a DAL component for accessing OAuth Client information
type ClientsDAL interface {
	GetClientByID(ID string) (*models.Client, error)
}

// PostgresClientsDAL is a Postgres implementation of the Clients DAL
type PostgresClientsDAL struct {
	db          *sql.DB
	clientCache map[string]*models.Client
}

// MustPostgresClientsDAL either returns a valid clients DAL service, or panics on error
func MustPostgresClientsDAL(config *models.Config) ClientsDAL {
	d, err := NewPostgresClientsDAL(config)
	if err != nil {
		panic(err)
	}

	return d
}

// NewPostgresClientsDAL returns a new ClientsDAL service using the provided config
func NewPostgresClientsDAL(config *models.Config) (ClientsDAL, error) {
	db, err := sql.Open("postgres", config.SQLConnectionString)
	if err != nil {
		return nil, err
	}

	return &PostgresClientsDAL{
		db:          db,
		clientCache: make(map[string]*models.Client),
	}, nil
}

// GetClientByID returns a pointer to the client with the specified ID
func (dal *PostgresClientsDAL) GetClientByID(ID string) (*models.Client, error) {
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
	var clientType string
	var uris sql.NullString
	found, err := utils.SQL.GetSingle(rows, &id, &secret, &clientType, &uris)
	if !found || err != nil {
		return nil, err
	}

	result := new(models.Client)
	result.ID = id
	result.Secret = secret
	eClientType, _ := enums.ParseClientType(clientType)
	result.Type = eClientType

	if uris.Valid {
		result.RedirectURIs = strings.Split(uris.String, ";")
	}

	// Populate the cache
	dal.clientCache[ID] = result
	return result, nil
}
