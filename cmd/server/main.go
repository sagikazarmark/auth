package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/docker/libtrust"
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
		issuer     string
		pkFile     string
		addr       string
		debug      bool
		err        error

		passwdFile string
		realm      string

		cert    string
		certKey string
	)

	flag.StringVar(&configFile, "config", "config.yaml", "Configuration file")
	flag.StringVar(&issuer, "issuer", "distribution-token-server", "Issuer string for token")
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

	var signingKey libtrust.PrivateKey

	if pkFile == "" {
		signingKey, err = libtrust.GenerateECP256PrivateKey()
		if err != nil {
			logger.Sugar().Fatalf("Error generating private key: %v", err)
		}
		logger.Sugar().Debugf("Using newly generated key with id %s", signingKey.KeyID())
	} else {
		signingKey, err = libtrust.LoadKeyFile(pkFile)
		if err != nil {
			logger.Sugar().Fatalf("Error loading key file %s: %v", pkFile, err)
		}
		logger.Sugar().Debugf("Loaded private key with id %s", signingKey.KeyID())
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

	// passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), 10)
	// if err != nil {
	// 	logger.Sugar().Fatalf("error generating password: %v", err)
	// }

	// // TODO: make expiration configurable
	// accessTokenIssuer := jwttoken.NewAccessTokenIssuer(issuer, signingKey, 15*time.Minute)
	// refreshTokenIssuer := jwttoken.NewRefreshTokenIssuer(issuer, signingKey)

	// passwordAuthenticator := authn.NewUserAuthenticator([]authn.User{
	// 	{
	// 		Enabled:      true,
	// 		Username:     "user",
	// 		PasswordHash: string(passwordHash),
	// 	},
	// })

	tokenIssuer := auth.TokenIssuer{
		AccessTokenIssuer:  accessTokenIssuer,
		RefreshTokenIssuer: refreshTokenIssuer,
	}

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
