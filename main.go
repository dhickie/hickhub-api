package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dhickie/hickhub-api/controllers"
	"github.com/dhickie/hickhub-api/models"
	"github.com/dhickie/hickhub-api/services"
	"github.com/gorilla/mux"
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

	// Create the required services
	authService, err := services.NewAuthService(config)
	if err != nil {
		panic(err)
	}

	// Create the required controllers
	authController := controllers.NewAuthController(authService)

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/oauth/authorize", authController.Authorise).Methods("POST")
	r.HandleFunc("/oauth/token", authController.Token).Methods("POST")

	// Listen for requests
	err = http.ListenAndServe(fmt.Sprintf(":%v", config.APIPort), r)
	if err != nil {
		panic(err)
	}

	select {}
}
