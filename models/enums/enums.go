package enums

// TokenType represents different types of access token used for calling the API
type TokenType int

// Scope represents the different API scopes available to consumers
type Scope int

// ClientType represents different types of API consuming clients
type ClientType int

const (
	// TokenTypeAccess tokens are used to normal API access from the website and third party partners
	TokenTypeAccess TokenType = iota
	// TokenTypeAPI tokens are special tokens with infinite lifetime used to call from a HickHub itself
	TokenTypeAPI
)

const (
	// ScopeMessaging scope provides access to messaging between the HickHub cloud and the HickHub itself
	ScopeMessaging Scope = iota
	// ScopeUser scope provides permission to access and modify user information
	ScopeUser
	// ScopeAdmin provides access to admin level features, such as user creation
	ScopeAdmin
)

const (
	// ClientTypePublic client types are publically authenticated users or partners
	ClientTypePublic ClientType = iota
	// ClientTypeConfidential partners are trusted 1st party applications
	ClientTypeConfidential
)

var tokenTypes = []string{
	"access",
	"api",
}

var scopes = []string{
	"messaging",
	"user",
	"admin",
}

var clientTypes = []string{
	"public",
	"confidential",
}

func (e TokenType) String() string {
	return tokenTypes[e]
}

func (e Scope) String() string {
	return scopes[e]
}

func (e ClientType) String() string {
	return clientTypes[e]
}

// ParseTokenType takes a given string and returns it's TokenType form, and a boolean indicating whether it was valid
func ParseTokenType(tokenType string) (TokenType, bool) {
	index := getIndex(tokenType, tokenTypes)
	if index < 0 {
		return TokenType(0), false
	}

	return TokenType(index), true
}

// ParseScope takes the given string and returns it's Scope form, and a boolean indicating whether it was valid
func ParseScope(scope string) (Scope, bool) {
	index := getIndex(scope, scopes)
	if index < 0 {
		return Scope(0), false
	}

	return Scope(index), true
}

// ParseClientType takes the given string and returns it's ClientType form, and a boolean indicating whether it was valid
func ParseClientType(clientType string) (ClientType, bool) {
	index := getIndex(clientType, clientTypes)
	if index < 0 {
		return ClientType(0), false
	}

	return ClientType(index), true
}

func getIndex(enumString string, enums []string) int {
	for i, v := range enums {
		if enumString == v {
			return i
		}
	}

	return -1
}
