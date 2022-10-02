package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/authz"
)

// Authorizer is the configuration for an auth.Authorizer.
type Authorizer struct {
	Type   string `yaml:"type"`
	Config AuthorizerFactory
}

func (c *Authorizer) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	var config AuthorizerFactory

	switch rawConfig.Type {
	case "default":
		var factory defaultAuthorizer

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

// AuthorizerFactory creates a new auth.Authorizer.
type AuthorizerFactory interface {
	CreateAuthorizer() (auth.Authorizer, error)
}

type defaultAuthorizer struct {
	AllowAnonymous bool `mapstructure:"allowAnonymous"`
}

func (c defaultAuthorizer) CreateAuthorizer() (auth.Authorizer, error) {
	return authz.NewDefaultAuthorizer(authz.NewDefaultRepositoryAuthorizer(c.AllowAnonymous), c.AllowAnonymous), nil
}
