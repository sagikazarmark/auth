package auth

import (
	"net/http"

	"github.com/gorilla/schema"
)

// Set a Decoder instance as a package global, because it caches
// meta-data about structs, and an instance can be shared safely.
var decoder = schema.NewDecoder()

type TokenHandler struct {
}

type TokenRequest struct {
	Service      string   `schema:"service"`
	OfflineToken bool     `schema:"offline_token"`
	ClientID     string   `schema:"client_id"`
	Scopes       []string `schema:"scope"`
}

func (s TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var request TokenRequest
	_ = decoder.Decode(&request, r.URL.Query())
}

// type TokenServer struct {
// }

// func (s TokenServer) HandleToken(w http.ResponseWriter, r *http.Request) {

// }

// func (s TokenServer) HandleOauth2(w http.ResponseWriter, r *http.Request) {

// }
