package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"strconv"
	"strings"
	"time"

	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	"github.com/docker/libtrust"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/distribution-auth/auth/auth"
	jwtauth "github.com/distribution-auth/auth/auth/accesstoken/jwt"
	"github.com/distribution-auth/auth/auth/authn"
	"github.com/distribution-auth/auth/auth/authz"
	"github.com/distribution-auth/auth/auth/refreshtoken"
)

func init() {
	jwt.MarshalSingleStringAsArray = false
}

func main() {
	var (
		tokenIssuer = jwtauth.Issuer{}
		pkFile      string
		addr        string
		debug       bool
		err         error

		passwdFile string
		realm      string

		cert    string
		certKey string
	)

	flag.StringVar(&tokenIssuer.Issuer, "issuer", "distribution-token-server", "Issuer string for token")
	flag.StringVar(&pkFile, "key", "", "Private key file")
	flag.StringVar(&addr, "addr", "localhost:8080", "Address to listen on")
	flag.BoolVar(&debug, "debug", false, "Debug mode")

	flag.StringVar(&passwdFile, "passwd", ".htpasswd", "Passwd file")
	flag.StringVar(&realm, "realm", "", "Authentication realm")

	flag.StringVar(&cert, "tlscert", "", "Certificate file for TLS")
	flag.StringVar(&certKey, "tlskey", "", "Certificate key for TLS")

	flag.Parse()

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if pkFile == "" {
		tokenIssuer.SigningKey, err = libtrust.GenerateECP256PrivateKey()
		if err != nil {
			logrus.Fatalf("Error generating private key: %v", err)
		}
		logrus.Debugf("Using newly generated key with id %s", tokenIssuer.SigningKey.KeyID())
	} else {
		tokenIssuer.SigningKey, err = libtrust.LoadKeyFile(pkFile)
		if err != nil {
			logrus.Fatalf("Error loading key file %s: %v", pkFile, err)
		}
		logrus.Debugf("Loaded private key with id %s", tokenIssuer.SigningKey.KeyID())
	}

	if realm == "" {
		logrus.Fatalf("Must provide realm")
	}

	ctx := dcontext.Background()

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), 10)
	if err != nil {
		logrus.Fatalf("error generating password: %v", err)
	}

	// TODO: make configurable
	tokenIssuer.Expiration = 15 * time.Minute

	refreshTokenRepository := &refreshtoken.InMemoryRefreshTokenRepository{}

	ts := &tokenServer{
		authenticator: authn.NewStaticPasswordAuthenticator(map[string]string{
			"user": string(passwordHash),
		}),
		authorizer:                authz.NewDefaultAuthorizer(authz.NewDefaultRepositoryAuthorizer(false), false),
		tokenIssuer:               tokenIssuer,
		refreshTokenAuthenticator: refreshtoken.NewDefaultRefreshTokenAuthenticator(refreshTokenRepository),
		refreshTokenIssuer:        refreshtoken.NewDefaultRefreshTokenIssuer(refreshTokenRepository),
	}

	router := mux.NewRouter()
	// router.Path("/token/").Methods("GET").Handler(handlerWithContext(ctx, ts.getToken))
	// router.Path("/token/").Methods("POST").Handler(handlerWithContext(ctx, ts.postToken))
	router.Path("/token").Methods("GET").Handler(handlerWithContext(ctx, ts.getToken))
	router.Path("/token").Methods("POST").Handler(handlerWithContext(ctx, ts.postToken))

	if cert == "" {
		err = http.ListenAndServe(addr, router)
	} else if certKey == "" {
		logrus.Fatalf("Must provide certficate (-tlscert) and key (-tlskey)")
	} else {
		err = http.ListenAndServeTLS(addr, cert, certKey, router)
	}

	if err != nil {
		logrus.Infof("Error serving: %v", err)
	}

}

// handlerWithContext wraps the given context-aware handler by setting up the
// request context from a base context.
func handlerWithContext(ctx context.Context, handler func(context.Context, http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := dcontext.WithRequest(ctx, r)
		logger := dcontext.GetRequestLogger(ctx)
		ctx = dcontext.WithLogger(ctx, logger)

		handler(ctx, w, r)
	})
}

func handleError(ctx context.Context, err error, w http.ResponseWriter) {
	ctx, w = dcontext.WithResponseWriter(ctx, w)

	if serveErr := errcode.ServeJSON(w, err); serveErr != nil {
		dcontext.GetResponseLogger(ctx).Errorf("error sending error response: %v", serveErr)
		return
	}

	dcontext.GetResponseLogger(ctx).Info("application error")
}

type tokenServer struct {
	authenticator             auth.PasswordAuthenticator
	authorizer                auth.Authorizer
	tokenIssuer               auth.AccessTokenIssuer
	refreshTokenAuthenticator auth.RefreshTokenAuthenticator
	refreshTokenIssuer        auth.RefreshTokenIssuer
}

type tokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// getToken handles authenticating the request and authorizing access to the
// requested scopes.
func (ts *tokenServer) getToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	dcontext.GetLogger(ctx).Info("getToken")

	params := r.URL.Query()
	service := params.Get("service")
	rawRequestedScopes := params["scope"]
	var offline bool
	if offlineStr := params.Get("offline_token"); offlineStr != "" {
		var err error
		offline, err = strconv.ParseBool(offlineStr)
		if err != nil {
			handleError(ctx, ErrorBadTokenOption.WithDetail(err), w)
			return
		}
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail("authentication failed"), w)
		return
	}

	subject, err := ts.authenticator.Authenticate(ctx, username, password)
	if err != nil && errors.Is(err, auth.ErrAuthenticationFailed) {
		handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail(err), w)
		return
	} else if err != nil {
		handleError(ctx, err, w)
		return
	}

	requestedScopes, err := auth.ParseScopes(rawRequestedScopes)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	grantedScopes, err := ts.authorizer.Authorize(ctx, subject, requestedScopes)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	token, err := ts.tokenIssuer.IssueAccessToken(subject, []string{service}, grantedScopes)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	dcontext.GetLogger(ctx).Info("authorized client")

	response := tokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
	}

	if offline && subject != nil {
		refreshToken, err := ts.refreshTokenIssuer.IssueRefreshToken(ctx, subject)
		if err != nil {
			handleError(ctx, err, w)
			return
		}

		response.RefreshToken = refreshToken
	}

	ctx, w = dcontext.WithResponseWriter(ctx, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dcontext.GetResponseLogger(ctx).Info("get token complete")
}

type postTokenResponse struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// postToken handles authenticating the request and authorizing access to the
// requested scopes.
func (ts *tokenServer) postToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType == "" {
		handleError(ctx, ErrorMissingRequiredField.WithDetail("missing grant_type value"), w)
		return
	}

	service := r.PostFormValue("service")
	if service == "" {
		handleError(ctx, ErrorMissingRequiredField.WithDetail("missing service value"), w)
		return
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		handleError(ctx, ErrorMissingRequiredField.WithDetail("missing client_id value"), w)
		return
	}

	var offline bool
	switch r.PostFormValue("access_type") {
	case "", "online":
	case "offline":
		offline = true
	default:
		handleError(ctx, ErrorUnsupportedValue.WithDetail("unknown access_type value"), w)
		return
	}

	requestedScopes, err := auth.ParseScopes(strings.Split(r.PostFormValue("scope"), " "))
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	var subject auth.Subject
	var rToken string
	switch grantType {
	case "refresh_token":
		rToken = r.PostFormValue("refresh_token")
		if rToken == "" {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("missing refresh_token value"), w)
			return
		}
		authenticatedSubject, err := ts.refreshTokenAuthenticator.Authenticate(ctx, rToken)
		if err != nil {
			handleError(ctx, err, w)
			return
		}
		// if rt.service != service {
		// 	handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail("invalid refresh token"), w)
		// 	return
		// }

		subject = authenticatedSubject
	case "password":
		username := r.PostFormValue("username")
		if username == "" {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("missing username value"), w)
			return
		}
		password := r.PostFormValue("password")
		if password == "" {
			handleError(ctx, ErrorUnsupportedValue.WithDetail("missing password value"), w)
			return
		}
		authenticatedSubject, err := ts.authenticator.Authenticate(ctx, username, password)
		if err != nil && errors.Is(err, auth.ErrAuthenticationFailed) {
			handleError(ctx, errcode.ErrorCodeUnauthorized.WithDetail(err), w)
			return
		} else if err != nil {
			handleError(ctx, err, w)
			return
		}
		subject = authenticatedSubject
	default:
		handleError(ctx, ErrorUnsupportedValue.WithDetail("unknown grant_type value"), w)
		return
	}

	grantedScopes, err := ts.authorizer.Authorize(ctx, subject, requestedScopes)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	token, err := ts.tokenIssuer.IssueAccessToken(subject, []string{service}, grantedScopes)
	if err != nil {
		handleError(ctx, err, w)
		return
	}

	dcontext.GetLogger(ctx).Info("authorized client")

	response := postTokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
		IssuedAt:  token.IssuedAt.Format(time.RFC3339),
		Scope:     auth.Scopes(grantedScopes).String(),
	}

	if offline && subject != nil {
		refreshToken, err := ts.refreshTokenIssuer.IssueRefreshToken(ctx, subject)
		if err != nil {
			handleError(ctx, err, w)
			return
		}

		rToken = refreshToken
	}

	if rToken != "" {
		response.RefreshToken = rToken
	}

	ctx, w = dcontext.WithResponseWriter(ctx, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	dcontext.GetResponseLogger(ctx).Info("post token complete")
}
