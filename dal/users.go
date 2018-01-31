package dal

import (
	"database/sql"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
)

// UsersDAL is a DAL component for accessing user data
type UsersDAL interface {
	GetUserByID(ID string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
}

// PostgresUsersDAL is a Postgres implementation of the UsersDAL interface
type PostgresUsersDAL struct {
	db            *sql.DB
	userCache     map[string]*models.User
	emailMapCache map[string]string
}

// MustPostgresUsersDAL either returns a valid PostgresUsersDAL object or panics on error
func MustPostgresUsersDAL(config *models.Config) UsersDAL {
	d, err := NewPostgresUsersDAL(config)
	if err != nil {
		panic(err)
	}

	return d
}

// NewPostgresUsersDAL returns a new PostgresUsersDAL service using the provided config
func NewPostgresUsersDAL(config *models.Config) (UsersDAL, error) {
	db, err := sql.Open("postgres", config.SQLConnectionString)
	if err != nil {
		return nil, err
	}

	return &PostgresUsersDAL{
		db:            db,
		userCache:     make(map[string]*models.User),
		emailMapCache: make(map[string]string),
	}, nil
}

// GetUserByID returns a pointer to the user with the specified ID
func (dal *PostgresUsersDAL) GetUserByID(ID string) (*models.User, error) {
	// Check the cache
	if val, ok := dal.userCache[ID]; ok {
		return val, nil
	}

	// Get from the database instead
	return dal.getFromDatabase(Queries.GetUserByID, ID)
}

// GetUserByEmail returns a pointer to the user with the specified email
func (dal *PostgresUsersDAL) GetUserByEmail(email string) (*models.User, error) {
	// Check the cache
	if val, ok := dal.emailMapCache[email]; ok {
		return dal.GetUserByID(val)
	}

	// Get from the database instead
	return dal.getFromDatabase(Queries.GetUserByEmail, email)
}

func (dal *PostgresUsersDAL) getFromDatabase(query, searchParam string) (*models.User, error) {
	rows, err := dal.db.Query(query, searchParam)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Get the result, if there is one
	result := new(models.User)
	found, err := utils.SQL.GetSingle(rows,
		&result.ID,
		&result.Email,
		&result.PassHash,
		&result.MessagingSubject)
	if !found || err != nil {
		return nil, err
	}

	// Populate the cache
	dal.populateCache(result)
	return result, nil
}

func (dal *PostgresUsersDAL) populateCache(user *models.User) {
	dal.userCache[user.ID] = user
	dal.emailMapCache[user.Email] = user.ID
}
