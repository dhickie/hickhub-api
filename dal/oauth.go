package dal

import (
	"database/sql"
	"strconv"
	"time"

	// Database driver for PostgreSQL
	_ "github.com/lib/pq"

	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/utils"
	"github.com/patrickmn/go-cache"
)

// OAuthDAL provides methods for getting and storing OAuth access token pairs
type OAuthDAL interface {
	GetAccessTokenPairByID(ID string) (*models.AccessTokenPair, error)
	GetAccessTokenPairByAccessToken(accessToken string) (*models.AccessTokenPair, error)
	GetAccessTokenPairByRefreshToken(refreshToken string) (*models.AccessTokenPair, error)
	InsertAccessTokenPair(tokenPair *models.AccessTokenPair) error
	DeleteAccessTokenPair(tokenPair *models.AccessTokenPair) error
}

// PostgresOAuthDAL is a Postgres implementation of the OAuthDAL interface
type PostgresOAuthDAL struct {
	db              *sql.DB
	tokenCache      *cache.Cache
	accessMapCache  *cache.Cache
	refreshMapCache *cache.Cache
}

// MustPostgresOAuthDAL either returns a valid PostgresOAuthDAL object or panics on error
func MustPostgresOAuthDAL(config *models.Config) OAuthDAL {
	d, err := NewPostgresOAuthDAL(config)
	if err != nil {
		panic(err)
	}

	return d
}

// NewPostgresOAuthDAL returns a new PostgresOAuthDAL service using the provided config
func NewPostgresOAuthDAL(config *models.Config) (OAuthDAL, error) {
	db, err := sql.Open("postgres", config.SQLConnectionString)
	if err != nil {
		return nil, err
	}

	expiration := time.Duration(config.RefreshTokenLifetime) * time.Second
	cleanup := 2 * time.Duration(config.RefreshTokenLifetime) * time.Second

	return &PostgresOAuthDAL{
		db:              db,
		tokenCache:      cache.New(expiration, cleanup),
		accessMapCache:  cache.New(expiration, cleanup),
		refreshMapCache: cache.New(expiration, cleanup),
	}, nil
}

// GetAccessTokenPairByID returns a pointer to the access token with the provided ID (if it exists)
func (dal *PostgresOAuthDAL) GetAccessTokenPairByID(ID string) (*models.AccessTokenPair, error) {
	// Check the cache first
	if cached, found := dal.tokenCache.Get(ID); found {
		return cached.(*models.AccessTokenPair), nil
	}

	// Go to... THE DATABASE
	return dal.getFromDatabase(Queries.GetTokenPairByID, ID)
}

// GetAccessTokenPairByAccessToken returns a pointer to the access token pair with the provided access token (if it exists)
func (dal *PostgresOAuthDAL) GetAccessTokenPairByAccessToken(accessToken string) (*models.AccessTokenPair, error) {
	// See if we can get the ID of the token pair from the cache
	if cached, found := dal.accessMapCache.Get(accessToken); found {
		return dal.GetAccessTokenPairByID(cached.(string))
	}

	// We need to go to the database :(
	return dal.getFromDatabase(Queries.GetTokenPairByAccessToken, accessToken)
}

// GetAccessTokenPairByRefreshToken returns a pointer to the access token pair with the provided refresh token (if it exists)
func (dal *PostgresOAuthDAL) GetAccessTokenPairByRefreshToken(refreshToken string) (*models.AccessTokenPair, error) {
	// See if we can get the ID of the token pair from the cache
	if cached, found := dal.refreshMapCache.Get(refreshToken); found {
		return dal.GetAccessTokenPairByID(cached.(string))
	}

	// We need to go to the database :(
	return dal.getFromDatabase(Queries.GetTokenPairByRefreshToken, refreshToken)
}

// InsertAccessTokenPair inserts the provided access token pair in to the database and populates the cache
func (dal *PostgresOAuthDAL) InsertAccessTokenPair(tokenPair *models.AccessTokenPair) error {
	var userID sql.NullInt64
	if tokenPair.UserID != "" {
		userID.Valid = true
		userID.Int64, _ = strconv.ParseInt(tokenPair.UserID, 10, 64)
	}

	// Add it to the database, and get the ID of the resulting row back
	rows, err := dal.db.Query(Queries.InsertTokenPair,
		tokenPair.AccessToken,
		tokenPair.RefreshToken,
		tokenPair.AccessTokenExpiry,
		tokenPair.RefreshTokenExpiry,
		userID,
		tokenPair.Scope)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Get resulting ID, and set it to the token pair
	var id string
	rows.Next()
	rows.Scan(&id)
	tokenPair.ID = id

	// Populate the cache
	dal.populateCache(tokenPair)
	return nil
}

// DeleteAccessTokenPair removes an access token pair from the database & cache
func (dal *PostgresOAuthDAL) DeleteAccessTokenPair(tokenPair *models.AccessTokenPair) error {
	// Remove from the database
	if _, err := dal.db.Query(Queries.DeleteTokenPair, tokenPair.ID); err != nil {
		return err
	}

	// Remove from the cache
	dal.deleteFromCache(tokenPair)
	return nil
}

// Gets an access token pair from the database, finding it using the specified query and search parameter
func (dal *PostgresOAuthDAL) getFromDatabase(query, searchParam string) (*models.AccessTokenPair, error) {
	rows, err := dal.db.Query(query, searchParam)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Get the result, if there is one
	result := new(models.AccessTokenPair)
	found, err := utils.SQL.GetSingle(rows,
		&result.ID,
		&result.AccessToken,
		&result.RefreshToken,
		&result.AccessTokenExpiry,
		&result.RefreshTokenExpiry,
		&result.UserID,
		&result.Scope)
	if !found || err != nil {
		return nil, err
	}

	// Populate the cache and return the result
	dal.populateCache(result)
	return result, nil
}

func (dal *PostgresOAuthDAL) populateCache(tokenPair *models.AccessTokenPair) {
	// Add the pair itself to the cache
	dal.tokenCache.Set(tokenPair.ID, tokenPair, cache.DefaultExpiration)

	// Add a map of the access token and refresh token to the pair's ID
	dal.accessMapCache.Set(tokenPair.AccessToken, tokenPair.ID, cache.DefaultExpiration)
	dal.refreshMapCache.Set(tokenPair.RefreshToken, tokenPair.ID, cache.DefaultExpiration)
}

func (dal *PostgresOAuthDAL) deleteFromCache(tokenPair *models.AccessTokenPair) {
	// Delete from the token cache itself
	dal.tokenCache.Delete(tokenPair.ID)

	// Delete from the token maps
	dal.accessMapCache.Delete(tokenPair.AccessToken)
	dal.refreshMapCache.Delete(tokenPair.RefreshToken)
}
