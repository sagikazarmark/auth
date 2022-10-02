package config

import (
	"fmt"

	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/authn"
	"github.com/distribution-auth/auth/pkg/slices"
)

// Authenticator is the configuration for an auth.PasswordAuthenticator.
type Authenticator struct {
	Type   string `yaml:"type"`
	Config AuthenticatorFactory
}

func (c *Authenticator) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	var config AuthenticatorFactory

	switch rawConfig.Type {
	case "user":
		var factory userAuthenticator

		err := decode(rawConfig.Config, &factory)
		if err != nil {
			return err
		}

		config = factory
	default:
		return fmt.Errorf("unknown authenticator type: %s", rawConfig.Type)
	}

	c.Config = config

	return nil
}

// AuthenticatorFactory creates a new auth.PasswordAuthenticator.
type AuthenticatorFactory interface {
	CreateAuthenticator() (auth.PasswordAuthenticator, error)
}

type userAuthenticator struct {
	Entries []user `mapstructure:"entries"`
}

type user struct {
	Enabled      bool              `mapstructure:"enabled"`
	Username     string            `mapstructure:"username"`
	PasswordHash string            `mapstructure:"passwordHash"`
	Attrs        map[string]string `mapstructure:"attributes"`
}

func (c userAuthenticator) CreateAuthenticator() (auth.PasswordAuthenticator, error) {
	entries := slices.Map(c.Entries, func(v user) authn.User {
		return authn.User{
			Enabled:      v.Enabled,
			Username:     v.Username,
			PasswordHash: v.PasswordHash,
			Attrs:        maps.Clone(v.Attrs),
		}
	})

	return authn.NewUserAuthenticator(entries), nil
}
