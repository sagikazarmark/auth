package config

import (
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/authz"
)

var (
	authorizerFactoriesMu sync.RWMutex
	authorizerFactories   = make(map[string]AuthorizerFactory)
)

// RegisterAuthorizerFactory makes an AuthenticatorFactory available by the provided name in configuration.
//
// If RegisterAuthorizerFactory is called twice with the same name or if factory is nil,
// it panics.
func RegisterAuthorizerFactory(name string, factory AuthorizerFactory) {
	authorizerFactoriesMu.Lock()
	defer authorizerFactoriesMu.Unlock()

	if factory == nil {
		panic("registering authorizer factory: factory is nil")
	}

	if _, dup := authorizerFactories[name]; dup {
		panic("registering authorizer factory: registration called twice for factory " + name)
	}

	authorizerFactories[name] = factory
}

func init() {
	RegisterAuthorizerFactory("default", defaultAuthorizer{})
}

// Authorizer is the configuration for an auth.Authorizer.
type Authorizer struct {
	AuthorizerFactory
}

func (c *Authorizer) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	authorizerFactoriesMu.RLock()
	factory, ok := authorizerFactories[rawConfig.Type]
	authorizerFactoriesMu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown authorizer type: %s", rawConfig.Type)
	}

	err = decode(rawConfig.Config, &factory)
	if err != nil {
		return err
	}

	c.AuthorizerFactory = factory

	return nil
}

// AuthorizerFactory creates a new auth.Authorizer.
type AuthorizerFactory interface {
	New() AuthorizerFactory
	CreateAuthorizer() (auth.Authorizer, error)
	Validate() error
}

type defaultAuthorizer struct {
	AllowAnonymous bool `mapstructure:"allowAnonymous"`
}

func (c defaultAuthorizer) New() AuthorizerFactory {
	return defaultAuthorizer{}
}

func (c defaultAuthorizer) CreateAuthorizer() (auth.Authorizer, error) {
	return authz.NewDefaultAuthorizer(authz.NewDefaultRepositoryAuthorizer(c.AllowAnonymous), c.AllowAnonymous), nil
}

func (c defaultAuthorizer) Validate() error {
	return nil
}
