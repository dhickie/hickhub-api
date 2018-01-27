package dal

import (
	"database/sql"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
)

// UsersDAL is a DAL component for accessing user data
type UsersDAL struct {
	db            *sql.DB
	userCache     map[string]*models.User
	emailMapCache map[string]string
}

// NewUsersDAL returns a new UsersDAL service using the provided config
func NewUsersDAL(config *models.Config) (*UsersDAL, error) {
	db, err := sql.Open("postgres", config.SQLConnectionString)
	if err != nil {
		return nil, err
	}

	return &UsersDAL{
		db:            db,
		userCache:     make(map[string]*models.User),
		emailMapCache: make(map[string]string),
	}, nil
}

// GetUserByID returns a pointer to the user with the specified ID
func (dal *UsersDAL) GetUserByID(ID string) (*models.User, error) {
	// Check the cache
	if val, ok := dal.userCache[ID]; ok {
		return val, nil
	}

	// Get from the database instead
	return dal.getFromDatabase(Queries.GetUserByID, ID)
}

// GetUserByEmail returns a pointer to the user with the specified email
func (dal *UsersDAL) GetUserByEmail(email string) (*models.User, error) {
	// Check the cache
	if val, ok := dal.emailMapCache[email]; ok {
		return dal.GetUserByID(val)
	}

	// Get from the database instead
	return dal.getFromDatabase(Queries.GetUserByEmail, email)
}

func (dal *UsersDAL) getFromDatabase(query, searchParam string) (*models.User, error) {
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

func (dal *UsersDAL) populateCache(user *models.User) {
	dal.userCache[user.ID] = user
	dal.emailMapCache[user.Email] = user.ID
}
