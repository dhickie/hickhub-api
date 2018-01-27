package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dhickie/hickhub-api/dal"
	"github.com/dhickie/hickhub-api/utils"

	"github.com/dhickie/hickhub-api/controllers"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/services"
	"github.com/gorilla/mux"
)

var (
	authDAL     *dal.OAuthDAL
	clientsDAL  *dal.ClientsDAL
	usersDAL    *dal.UsersDAL
	authService *services.AuthService
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
	createDALs(config)

	// Create the required services
	authService, err = services.NewAuthService(config, authDAL, usersDAL, clientsDAL)
	if err != nil {
		panic(err)
	}

	// Create the required controllers
	authController := controllers.NewAuthController(authService)
	userController := controllers.NewUserController(usersDAL)

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/oauth/authorize", authController.Authorise).Methods("POST")
	r.HandleFunc("/oauth/token", authController.Token).Methods("POST")

	r.HandleFunc("/user/subject", userAuthMiddleware{"messaging", userController.Subject}.Handle).Methods("GET")

	// Listen for requests
	err = http.ListenAndServe(fmt.Sprintf(":%v", config.APIPort), r)
	if err != nil {
		panic(err)
	}

	select {}
}

func createDALs(config *models.Config) {
	var err error

	authDAL, err = dal.NewOAuthDAL(config)
	if err != nil {
		panic(err)
	}

	clientsDAL, err = dal.NewClientsDAL(config)
	if err != nil {
		panic(err)
	}

	usersDAL, err = dal.NewUsersDAL(config)
	if err != nil {
		panic(err)
	}
}

type userAuthMiddleware struct {
	requiredScope string
	h             func(http.ResponseWriter, string)
}

func (m userAuthMiddleware) Handle(w http.ResponseWriter, r *http.Request) {
	// Verify that the request has a valid customer access token
	token, found := utils.HTTP.GetBearerToken(r)
	if !found {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	tokenPair, err := authDAL.GetAccessTokenPairByAccessToken(token)
	if err != nil {
		utils.HTTP.RespondInternalServerError(w, err.Error())
		return
	}

	if tokenPair == nil {
		utils.HTTP.RespondUnauthorized(w)
		return
	}

	// Verify that the token is valid for the required scope, and hasn't expired
	if tokenPair.Scope != m.requiredScope || tokenPair.AccessTokenExpiry.Before(time.Now()) {
		utils.HTTP.RespondForbidden(w)
		return
	}

	// All good, pass the associated user ID on to the handler
	m.h(w, tokenPair.UserID)
}
