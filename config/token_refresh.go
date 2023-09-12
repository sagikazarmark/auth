package config

import (
	"fmt"
	"sync"

	"github.com/docker/libtrust"
	"gopkg.in/yaml.v3"

	"github.com/sagikazarmark/registry-auth/auth"
	"github.com/sagikazarmark/registry-auth/auth/token/jwt"
)

var (
	refreshTokenIssuerFactoriesMu sync.RWMutex
	refreshTokenIssuerFactories   = make(map[string]RefreshTokenIssuerFactory)
)

// RegisterRefreshTokenIssuerFactory makes an AuthenticatorFactory available by the provided name in configuration.
//
// If RegisterRefreshTokenIssuerFactory is called twice with the same name or if factory is nil,
// it panics.
func RegisterRefreshTokenIssuerFactory(name string, factory RefreshTokenIssuerFactory) {
	refreshTokenIssuerFactoriesMu.Lock()
	defer refreshTokenIssuerFactoriesMu.Unlock()

	if factory == nil {
		panic("registering refresh token issuer factory: factory is nil")
	}

	if _, dup := refreshTokenIssuerFactories[name]; dup {
		panic("registering refresh token issuer factory: registration called twice for factory " + name)
	}

	refreshTokenIssuerFactories[name] = factory
}

func init() {
	RegisterRefreshTokenIssuerFactory("jwt", jwtRefreshTokenIssuer{})
}

// RefreshTokenIssuer is the configuration for an auth.RefreshTokenIssuer.
type RefreshTokenIssuer struct {
	RefreshTokenIssuerFactory
}

func (c *RefreshTokenIssuer) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	refreshTokenIssuerFactoriesMu.RLock()
	factory, ok := refreshTokenIssuerFactories[rawConfig.Type]
	refreshTokenIssuerFactoriesMu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown refresh token issuer type: %s", rawConfig.Type)
	}

	err = decode(rawConfig.Config, &factory)
	if err != nil {
		return err
	}

	c.RefreshTokenIssuerFactory = factory

	return nil
}

// RefreshTokenIssuerFactory creates a new auth.RefreshTokenIssuer.
type RefreshTokenIssuerFactory interface {
	New() RefreshTokenIssuerFactory
	CreateRefreshTokenIssuer() (auth.RefreshTokenIssuer, error)
	Validate() error
}

type jwtRefreshTokenIssuer struct {
	Issuer         string `mapstructure:"issuer"`
	PrivateKeyFile string `mapstructure:"privateKeyFile"`
}

func (c jwtRefreshTokenIssuer) New() RefreshTokenIssuerFactory {
	return jwtRefreshTokenIssuer{}
}

func (c jwtRefreshTokenIssuer) CreateRefreshTokenIssuer() (auth.RefreshTokenIssuer, error) {
	signingKey, err := libtrust.LoadKeyFile(c.PrivateKeyFile)
	if err != nil {
		return nil, err
	}

	return jwt.NewRefreshTokenIssuer(c.Issuer, signingKey), nil
}

func (c jwtRefreshTokenIssuer) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("refresh token issuer: jwt: issuer is required")
	}

	if c.PrivateKeyFile == "" {
		return fmt.Errorf("refresh token issuer: jwt: privateKeyFile is required")
	}

	return nil
}
