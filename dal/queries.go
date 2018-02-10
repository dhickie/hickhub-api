package dal

// Queries is a dummy struct containing all the DAL SQL queries we use
var Queries = queriesStruct{
	GetTokenPairByID:           getTokenPairByID,
	GetTokenPairByAccessToken:  getTokenPairByAccessToken,
	GetTokenPairByRefreshToken: getTokenPairByRefreshToken,
	InsertTokenPair:            insertTokenPair,
	DeleteTokenPair:            deleteTokenPair,
	GetClientByID:              getClientByID,
	GetUserByID:                getUserByID,
	GetUserByEmail:             getUserByEmail,
}

type queriesStruct struct {
	GetTokenPairByID           string
	GetTokenPairByAccessToken  string
	GetTokenPairByRefreshToken string
	InsertTokenPair            string
	DeleteTokenPair            string
	GetClientByID              string
	GetUserByID                string
	GetUserByEmail             string
}

// Getting OAuth Tokens
const getTokenPairByID = getTokenPair + " WHERE id = $1"
const getTokenPairByAccessToken = getTokenPair + " WHERE access_token = $1"
const getTokenPairByRefreshToken = getTokenPair + " WHERE refresh_token = $1"
const getTokenPair = `
SELECT id,
	access_token,
	refresh_token,
	access_token_expiry,
	refresh_token_expiry,
	user_id,
	scope
FROM oauthtokens
`

// Inserting/Removing OAuth tokens
const insertTokenPair = `
INSERT INTO oauthtokens(
	access_token,
	refresh_token,
	access_token_expiry,
	refresh_token_expiry,
	user_id,
	scope)
VALUES(
	$1,
	$2,
	$3,
	$4,
	$5,
	$6)
RETURNING id
`
const deleteTokenPair = `
DELETE FROM oauthtokens
WHERE id = $1
`

// Getting clients
const getClientByID = `
SELECT id,
	secret,
	type,
	redirect_uris
FROM clients
WHERE id = $1
`

// Getting users
const getUserByID = getUser + " WHERE id = $1"
const getUserByEmail = getUser + " WHERE email = $1"
const getUser = `
SELECT id,
	email,
	pass_hash,
	messaging_subject,
	security_question,
	security_answer
FROM users
`
