package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/schema"
)

// Set a Decoder instance as a package global, because it caches
// meta-data about structs, and an instance can be shared safely.
var decoder = schema.NewDecoder()

// TokenServer implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/index.md
type TokenServer struct {
	Service TokenService
}

func handleError(err error, w http.ResponseWriter) {
	if errors.Is(err, ErrAuthenticationFailed) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return
	}

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// TokenHandler implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
func (s TokenServer) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var tokenRequest TokenRequest

	err := decoder.Decode(&tokenRequest, r.URL.Query())
	if err != nil {
		handleError(err, w)
		return
	}

	username, password, ok := r.BasicAuth()
	tokenRequest.Anonymous = !ok
	tokenRequest.Username = username
	tokenRequest.Password = password

	response, err := s.Service.TokenHandler(r.Context(), tokenRequest)
	if err != nil {
		handleError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// OAuth2Handler implements the [Docker Registry v2 OAuth2 authentication] specification.
//
// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
func (s TokenServer) OAuth2Handler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		handleError(err, w)
		return
	}

	var tokenRequest OAuth2TokenRequest

	err = decoder.Decode(&tokenRequest, r.PostForm)
	if err != nil {
		handleError(err, w)
		return
	}

	response, err := s.Service.OAuth2TokenHandler(r.Context(), tokenRequest)
	if err != nil {
		handleError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
