package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/models/enums"
	"github.com/dhickie/hickhub-api/utils"

	"github.com/dhickie/hickhub-api/controllers"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/services"
	"github.com/gorilla/mux"
)

var (
	authDAL          dal.OAuthDAL
	clientsDAL       dal.ClientsDAL
	usersDAL         dal.UsersDAL
	authService      services.AuthService
	messagingService services.MessagingService
)

func main() {
	// Read the config
	configData, err := ioutil.ReadFile("config.json")
	if err != nil {
		panic(err)
	}

	config := new(models.Config)
	err = json.Unmarshal(configData, config)
	if err != nil {
		panic(err)
	}

	// Create all the DAL services
	authDAL = dal.MustPostgresOAuthDAL(config)
	clientsDAL = dal.MustPostgresClientsDAL(config)
	usersDAL = dal.MustPostgresUsersDAL(config)

	// Create the required services
	authService = services.MustHickHubAuthService(config, authDAL, usersDAL, clientsDAL)
	messagingService = services.MustNatsMessagingService(config)

	// Create the required controllers
	authController := controllers.NewAuthController(authService)
	userController := controllers.NewUserController(usersDAL, authService)
	messagingController := controllers.NewMessagingController(usersDAL, messagingService)
	registrationController := controllers.NewRegistrationController(usersDAL, authService)

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/oauth/authorize", authController.Authorise).Methods("POST")
	r.HandleFunc("/oauth/token", authController.Token).Methods("POST")

	r.HandleFunc("/user/messaging/subject", userAuthMiddleware{enums.ScopeMessaging, userController.Subject}.Handle).Methods("GET")
	r.HandleFunc("/user/messaging/request", userAuthMiddleware{enums.ScopeMessaging, messagingController.Request}.Handle).Methods("POST")
	r.HandleFunc("/user/email", userAuthMiddleware{enums.ScopeUser, userController.ChangeEmail}.Handle).Methods("POST")
	r.HandleFunc("/user/password", userAuthMiddleware{enums.ScopeUser, userController.ChangePassword}.Handle).Methods("POST")

	r.HandleFunc("/registration/user", confidentialAuthMiddleware{enums.ScopeAdmin, registrationController.RegisterNewUser}.Handle).Methods("POST")
	r.HandleFunc("/registration/email/{email}/available", confidentialAuthMiddleware{enums.ScopeAdmin, registrationController.GetEmailAvailability}.Handle).Methods("GET")

	// Listen for requests
	err = http.ListenAndServe(fmt.Sprintf(":%v", config.APIPort), crossOriginMiddleware{r})
	if err != nil {
		panic(err)
	}
}

type userAuthMiddleware struct {
	requiredScope enums.Scope
	h             func(http.ResponseWriter, string, []byte)
}

func (m userAuthMiddleware) Handle(w http.ResponseWriter, r *http.Request) {
	valid, body, userID := validateAccessToken(w, r, m.requiredScope)
	if valid {
		// All good, pass the associated user ID on to the handler
		m.h(w, userID, body)
	}
}

type confidentialAuthMiddleware struct {
	requiredScope enums.Scope
	h             func(http.ResponseWriter, map[string]string, []byte)
}

func (m confidentialAuthMiddleware) Handle(w http.ResponseWriter, r *http.Request) {
	valid, body, _ := validateAccessToken(w, r, m.requiredScope)
	if valid {
		m.h(w, mux.Vars(r), body)
	}
}

type crossOriginMiddleware struct {
	h http.Handler
}

func (m crossOriginMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	m.h.ServeHTTP(w, r)
}

// Helper function to validate the access token provided with requests to the API
func validateAccessToken(w http.ResponseWriter, r *http.Request, requiredScope enums.Scope) (bool, []byte, string) {
	// Verify that the request has an access token in it
	token, found := utils.HTTP.GetBearerToken(r)
	if !found {
		utils.HTTP.RespondUnauthorized(w)
		return false, nil, ""
	}

	tokenPair, err := authDAL.GetAccessTokenPairByAccessToken(token)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return false, nil, ""
	}

	if tokenPair == nil {
		utils.HTTP.RespondUnauthorized(w)
		return false, nil, ""
	}

	// Verify that the token is valid for the required scope, and hasn't expired
	if utils.Auth.ContainsScope(tokenPair.Scopes, requiredScope) || tokenPair.AccessTokenExpiry.Before(time.Now()) {
		utils.HTTP.RespondForbidden(w)
		return false, nil, ""
	}

	// Get the body of the request
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return false, nil, ""
	}

	return true, body, tokenPair.UserID
}
