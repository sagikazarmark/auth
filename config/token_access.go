package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/token/jwt"
	"github.com/docker/libtrust"
)

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

	var config AccessTokenIssuerFactory

	switch rawConfig.Type {
	case "jwt":
		var factory jwtAccessTokenIssuer

		err := decode(rawConfig.Config, &factory)
		if err != nil {
			return err
		}

		config = factory

	default:
		return fmt.Errorf("unknown access token issuer type: %s", rawConfig.Type)
	}

	c.Config = config

	return nil
}

// AccessTokenIssuerFactory creates a new auth.AccessTokenIssuer.
type AccessTokenIssuerFactory interface {
	CreateAccessTokenIssuer() (auth.AccessTokenIssuer, error)
	Validate() error
}

type jwtAccessTokenIssuer struct {
	Issuer         string        `mapstructure:"issuer"`
	PrivateKeyFile string        `mapstructure:"privateKeyFile"`
	Expiration     time.Duration `mapstructure:"expiration"`
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
