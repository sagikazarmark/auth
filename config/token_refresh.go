package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/token/jwt"
	"github.com/docker/libtrust"
)

// RefreshTokenIssuer is the configuration for an auth.RefreshTokenIssuer.
type RefreshTokenIssuer struct {
	Type   string `yaml:"type"`
	Config RefreshTokenIssuerFactory
}

func (c *RefreshTokenIssuer) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	var config RefreshTokenIssuerFactory

	switch rawConfig.Type {
	case "jwt":
		var factory jwtRefreshTokenIssuer

		err := decode(rawConfig.Config, &factory)
		if err != nil {
			return err
		}

		config = factory

	default:
		return fmt.Errorf("unknown refresh token issuer type: %s", rawConfig.Type)
	}

	c.Config = config

	return nil
}

// RefreshTokenIssuerFactory creates a new auth.RefreshTokenIssuer.
type RefreshTokenIssuerFactory interface {
	CreateRefreshTokenIssuer() (auth.RefreshTokenIssuer, error)
}

type jwtRefreshTokenIssuer struct {
	Issuer         string `mapstructure:"issuer"`
	PrivateKeyFile string `mapstructure:"privateKeyFile"`
}

func (c jwtRefreshTokenIssuer) CreateRefreshTokenIssuer() (auth.RefreshTokenIssuer, error) {
	signingKey, err := libtrust.LoadKeyFile(c.PrivateKeyFile)
	if err != nil {
		return nil, err
	}

	return jwt.NewRefreshTokenIssuer(c.Issuer, signingKey), nil
}
