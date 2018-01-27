package utils

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

type httpUtil struct{}

// HTTP provides access to HttpUtil functions
var HTTP = httpUtil{}

// ReadRequestBody reads the body of the provided request and unmarshals it in to the provided model.
// model should be a pointer to the struct the request contains
func (u *httpUtil) ReadRequestBody(r *http.Request, model interface{}) error {
	// Ready the request body
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		return err
	}

	// Deserialise it in to the provided body
	return json.Unmarshal(body, model)
}

func (u *httpUtil) GetBearerToken(r *http.Request) (string, bool) {
	header := r.Header["Authorization"]
	if header == nil || len(header) == 0 {
		return "", false
	}
	value := header[0]

	if !strings.HasPrefix(strings.ToLower(value), "bearer") || len(value) < 9 {
		return "", false
	}

	return value[7:], true
}

func (u *httpUtil) RespondOK(w http.ResponseWriter, response interface{}) {
	// Marshal the response body
	body, err := json.Marshal(response)
	if err != nil {
		// Respond with an internal server error
		u.RespondInternalServerError(w, err.Error())
		return
	}

	w.Write(body)
}

// RespondBadRequest will return a bad request http response with the err as the body
func (u *httpUtil) RespondBadRequest(w http.ResponseWriter, err string) {
	http.Error(w, err, 400)
}

// RespondInternalServerError will return a 500 http response with the err as the body
func (u *httpUtil) RespondInternalServerError(w http.ResponseWriter, err string) {
	http.Error(w, err, 500)
}

// RespondInternalServerError will return a an empty unauthorized response
func (u *httpUtil) RespondUnauthorized(w http.ResponseWriter) {
	http.Error(w, "", 401)
}

// RespondForbidden will return an empty forbidden response
func (u *httpUtil) RespondForbidden(w http.ResponseWriter) {
	http.Error(w, "", 403)
}

// RespondNotFound will return an empty not found response
func (u *httpUtil) RespondNotFound(w http.ResponseWriter) {
	http.Error(w, "", 404)
}
