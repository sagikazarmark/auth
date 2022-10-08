package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/authn"
	"github.com/distribution-auth/auth/config"
)

func init() {
	jwt.MarshalSingleStringAsArray = false
}

func main() {
	var (
		configFile string
		addr       string
		debug      bool
		err        error

		realm string
	)

	flag.StringVar(&configFile, "config", "config.yaml", "Configuration file")
	flag.StringVar(&addr, "addr", "localhost:8080", "Address to listen on")
	flag.BoolVar(&debug, "debug", false, "Debug mode")
	flag.StringVar(&realm, "realm", "", "Authentication realm")
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

	if realm == "" {
		logger.Sugar().Fatalf("Must provide realm")
	}

	var config config.Config

	{
		file, err := os.Open(configFile)
		if err != nil {
			logger.Sugar().Fatalf("loading config file: %v", err)
		}
		defer file.Close()

		decoder := yaml.NewDecoder(file)

		err = decoder.Decode(&config)
		if err != nil {
			logger.Sugar().Fatalf("decoding config file: %v", err)
		}
	}

	passwordAuthenticator, err := config.Authenticator.Config.CreateAuthenticator()
	if err != nil {
		logger.Sugar().Fatalf("creating authenticator: %v", err)
	}

	accessTokenIssuer, err := config.AccessTokenIssuer.Config.CreateAccessTokenIssuer()
	if err != nil {
		logger.Sugar().Fatalf("creating access token issuer: %v", err)
	}

	refreshTokenIssuer, err := config.RefreshTokenIssuer.Config.CreateRefreshTokenIssuer()
	if err != nil {
		logger.Sugar().Fatalf("creating refresh token issuer: %v", err)
	}

	tokenIssuer := auth.TokenIssuer{
		AccessTokenIssuer:  accessTokenIssuer,
		RefreshTokenIssuer: refreshTokenIssuer,
	}

	// TODO: configuration
	refreshTokenAuthenticator := authn.NewRefreshTokenAuthenticator(refreshTokenIssuer.(authn.RefreshTokenVerifier), passwordAuthenticator.(authn.SubjectRepository))

	authenticator := auth.Authenticator{
		PasswordAuthenticator:     passwordAuthenticator,
		RefreshTokenAuthenticator: refreshTokenAuthenticator,
	}

	authorizer, err := config.Authorizer.Config.CreateAuthorizer()
	if err != nil {
		logger.Sugar().Fatalf("creating authorizer issuer: %v", err)
	}

	service := auth.TokenServiceImpl{
		Authenticator: authenticator,
		Authorizer:    authorizer,
		// Authorizer:    authz.NewDefaultAuthorizer(authz.NewDefaultRepositoryAuthorizer(false), false),
		TokenIssuer: tokenIssuer,
		Logger:      logger,
	}

	server := auth.TokenServer{
		Service: service,
	}

	router := mux.NewRouter()
	router.Path("/token").Methods("GET").HandlerFunc(server.TokenHandler)
	router.Path("/token").Methods("POST").HandlerFunc(server.OAuth2Handler)

	err = http.ListenAndServe(addr, router)
	if err != nil {
		logger.Sugar().Infof("Error serving: %v", err)
	}
}
