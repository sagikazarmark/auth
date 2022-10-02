package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// TokenServer implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/index.md
type TokenServer struct {
	Authenticator             PasswordAuthenticator
	Authorizer                Authorizer
	AccessTokenIssuer         AccessTokenIssuer
	RefreshTokenAuthenticator RefreshTokenAuthenticator
	RefreshTokenIssuer        RefreshTokenIssuer

	Logger *zap.Logger
}

func handleError(err error, w http.ResponseWriter) {
	if errors.Is(err, ErrAuthenticationFailed) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return
	}

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

type tokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// TokenHandler implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
func (s TokenServer) TokenHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	var offline bool
	if offlineStr := params.Get("offline_token"); offlineStr != "" {
		var err error

		offline, err = strconv.ParseBool(offlineStr)
		if err != nil {
			// TODO: return error?
			s.Logger.Debug("invalid offline value")
		}
	}

	var subject Subject

	if username, password, ok := r.BasicAuth(); ok {
		var err error

		subject, err = s.Authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			handleError(err, w)
			return
		}
	}

	service := params.Get("service")
	// TODO: handle missing service value

	// TODO: missing client_id

	requestedScopes, err := ParseScopes(params["scope"])
	if err != nil {
		handleError(err, w)
		return
	}

	grantedScopes, err := s.Authorizer.Authorize(r.Context(), subject, requestedScopes)
	if err != nil {
		handleError(err, w)
		return
	}

	token, err := s.AccessTokenIssuer.IssueAccessToken(subject, []string{service}, grantedScopes)
	if err != nil {
		handleError(err, w)
		return
	}

	s.Logger.Debug("client authorized")

	response := tokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
	}

	if offline && subject != nil {
		refreshToken, err := s.RefreshTokenIssuer.IssueRefreshToken(r.Context(), subject)
		if err != nil {
			handleError(err, w)
			return
		}

		response.RefreshToken = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type oauth2Response struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// OAuth2Handler implements the [Docker Registry v2 OAuth2 authentication] specification.
//
// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
func (s TokenServer) OAuth2Handler(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType == "" {
		// TODO: OAuth2 error: missing grant_type value
		return
	}

	service := r.PostFormValue("service")
	if service == "" {
		// TODO: OAuth2 error: missing service value
		return
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		// TODO: OAuth2 error: missing client_id value
		return
	}

	var offline bool
	switch r.PostFormValue("access_type") {
	case "", "online":
	case "offline":
		offline = true
	default:
		// TODO: OAuth2 error: missing access_type value
		return
	}

	var subject Subject
	var refreshToken string

	switch grantType {
	case "refresh_token":
		refreshToken = r.PostFormValue("refresh_token")
		if refreshToken == "" {
			// TODO: OAuth2 error: missing refresh_token value
			return
		}

		var err error

		subject, err = s.RefreshTokenAuthenticator.Authenticate(r.Context(), refreshToken)
		if err != nil {
			handleError(err, w)
			return
		}

		// TODO: check if service is the same as stored in the refresh token
	case "password":
		username := r.PostFormValue("username")
		if username == "" {
			// TODO: OAuth2 error: missing username value
			return
		}
		password := r.PostFormValue("password")
		if password == "" {
			// TODO: OAuth2 error: missing password value
			return
		}

		var err error

		subject, err = s.Authenticator.Authenticate(r.Context(), username, password)
		if err != nil {
			handleError(err, w)
			return
		}
	default:
		// TODO: OAuth2 error: unknown grant_type value
		return
	}

	requestedScopes, err := ParseScopes(strings.Split(r.PostFormValue("scope"), " "))
	if err != nil {
		handleError(err, w)
		return
	}

	grantedScopes, err := s.Authorizer.Authorize(r.Context(), subject, requestedScopes)
	if err != nil {
		handleError(err, w)
		return
	}

	token, err := s.AccessTokenIssuer.IssueAccessToken(subject, []string{service}, grantedScopes)
	if err != nil {
		handleError(err, w)
		return
	}

	s.Logger.Debug("client authorized")

	response := oauth2Response{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
		IssuedAt:  token.IssuedAt.Format(time.RFC3339),
		Scope:     Scopes(grantedScopes).String(),
	}

	if offline && subject != nil && grantType == "refresh_token" {
		token, err := s.RefreshTokenIssuer.IssueRefreshToken(r.Context(), subject)
		if err != nil {
			handleError(err, w)
			return
		}

		refreshToken = token
	}

	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
