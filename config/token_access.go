package config

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/token/jwt"
	"github.com/docker/libtrust"
)

var (
	accessTokenIssuerFactoriesMu sync.RWMutex
	accessTokenIssuerFactories   = make(map[string]AccessTokenIssuerFactory)
)

// RegisterAccessTokenIssuerFactory makes an AuthenticatorFactory available by the provided name in configuration.
//
// If RegisterAccessTokenIssuerFactory is called twice with the same name or if factory is nil,
// it panics.
func RegisterAccessTokenIssuerFactory(name string, factory AccessTokenIssuerFactory) {
	accessTokenIssuerFactoriesMu.Lock()
	defer accessTokenIssuerFactoriesMu.Unlock()

	if factory == nil {
		panic("registering access token issuer factory: factory is nil")
	}

	if _, dup := accessTokenIssuerFactories[name]; dup {
		panic("registering access token issuer factory: registration called twice for factory " + name)
	}

	accessTokenIssuerFactories[name] = factory
}

func init() {
	RegisterAccessTokenIssuerFactory("jwt", jwtAccessTokenIssuer{})
}

// AccessTokenIssuer is the configuration for an auth.AccessTokenIssuer.
type AccessTokenIssuer struct {
	Config AccessTokenIssuerFactory
}

func (c *AccessTokenIssuer) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	accessTokenIssuerFactoriesMu.RLock()
	factory, ok := accessTokenIssuerFactories[rawConfig.Type]
	accessTokenIssuerFactoriesMu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown access token issuer type: %s", rawConfig.Type)
	}

	err = decode(rawConfig.Config, &factory)
	if err != nil {
		return err
	}

	c.Config = factory

	return nil
}

// AccessTokenIssuerFactory creates a new auth.AccessTokenIssuer.
type AccessTokenIssuerFactory interface {
	New() AccessTokenIssuerFactory
	CreateAccessTokenIssuer() (auth.AccessTokenIssuer, error)
	Validate() error
}

type jwtAccessTokenIssuer struct {
	Issuer         string        `mapstructure:"issuer"`
	PrivateKeyFile string        `mapstructure:"privateKeyFile"`
	Expiration     time.Duration `mapstructure:"expiration"`
}

func (c jwtAccessTokenIssuer) New() AccessTokenIssuerFactory {
	return jwtAccessTokenIssuer{}
}

func (c jwtAccessTokenIssuer) CreateAccessTokenIssuer() (auth.AccessTokenIssuer, error) {
	signingKey, err := libtrust.LoadKeyFile(c.PrivateKeyFile)
	if err != nil {
		return nil, err
	}

	return jwt.NewAccessTokenIssuer(c.Issuer, signingKey, c.Expiration), nil
}

func (c jwtAccessTokenIssuer) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("access token issuer: jwt: issuer is required")
	}

	if c.PrivateKeyFile == "" {
		return fmt.Errorf("access token issuer: jwt: privateKeyFile is required")
	}

	if c.Expiration == 0 {
		return fmt.Errorf("access token issuer: jwt: expiration is required")
	}

	return nil
}
