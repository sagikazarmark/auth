package main

import (
	"flag"
	"net/http"
	"time"

	"github.com/docker/libtrust"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
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

	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	if debug {
		logger, err = zap.NewDevelopment()
		if err != nil {
			panic(err)
		}
	}

	if pkFile == "" {
		tokenIssuer.SigningKey, err = libtrust.GenerateECP256PrivateKey()
		if err != nil {
			logger.Sugar().Fatalf("Error generating private key: %v", err)
		}
		logger.Sugar().Debugf("Using newly generated key with id %s", tokenIssuer.SigningKey.KeyID())
	} else {
		tokenIssuer.SigningKey, err = libtrust.LoadKeyFile(pkFile)
		if err != nil {
			logger.Sugar().Fatalf("Error loading key file %s: %v", pkFile, err)
		}
		logger.Sugar().Debugf("Loaded private key with id %s", tokenIssuer.SigningKey.KeyID())
	}

	if realm == "" {
		logger.Sugar().Fatalf("Must provide realm")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), 10)
	if err != nil {
		logger.Sugar().Fatalf("error generating password: %v", err)
	}

	// TODO: make configurable
	tokenIssuer.Expiration = 15 * time.Minute

	refreshTokenRepository := &refreshtoken.InMemoryRefreshTokenRepository{}

	service := auth.TokenServiceImpl{
		Authenticator: authn.NewStaticPasswordAuthenticator(map[string]string{
			"user": string(passwordHash),
		}),
		Authorizer:                authz.NewDefaultAuthorizer(authz.NewDefaultRepositoryAuthorizer(false), false),
		AccessTokenIssuer:         tokenIssuer,
		RefreshTokenAuthenticator: refreshtoken.NewDefaultRefreshTokenAuthenticator(refreshTokenRepository),
		RefreshTokenIssuer:        refreshtoken.NewDefaultRefreshTokenIssuer(refreshTokenRepository),
		Logger:                    logger,
	}

	server := auth.TokenServer{
		Service: service,
	}

	router := mux.NewRouter()
	router.Path("/token").Methods("GET").HandlerFunc(server.TokenHandler)
	router.Path("/token").Methods("POST").HandlerFunc(server.OAuth2Handler)

	if cert == "" {
		err = http.ListenAndServe(addr, router)
	} else if certKey == "" {
		logger.Sugar().Fatalf("Must provide certficate (-tlscert) and key (-tlskey)")
	} else {
		err = http.ListenAndServeTLS(addr, cert, certKey, router)
	}

	if err != nil {
		logger.Sugar().Infof("Error serving: %v", err)
	}
}
