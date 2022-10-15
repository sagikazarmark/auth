package config

import (
	"fmt"
	"sync"

	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/auth/authn"
	"github.com/distribution-auth/auth/pkg/slices"
)

var (
	authenticatorFactoriesMu sync.RWMutex
	authenticatorFactories   = make(map[string]AuthenticatorFactory)
)

// RegisterAuthenticatorFactory makes an AuthenticatorFactory available by the provided name in configuration.
//
// If RegisterAuthenticatorFactory is called twice with the same name or if factory is nil,
// it panics.
func RegisterAuthenticatorFactory(name string, factory AuthenticatorFactory) {
	authenticatorFactoriesMu.Lock()
	defer authenticatorFactoriesMu.Unlock()

	if factory == nil {
		panic("registering authenticator factory: factory is nil")
	}

	if _, dup := authenticatorFactories[name]; dup {
		panic("registering authenticator factory: registration called twice for factory " + name)
	}

	authenticatorFactories[name] = factory
}

func init() {
	RegisterAuthenticatorFactory("user", userAuthenticator{})
}

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

	c.Type = rawConfig.Type

	authenticatorFactoriesMu.RLock()
	factory, ok := authenticatorFactories[rawConfig.Type]
	authenticatorFactoriesMu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown authenticator type: %s", rawConfig.Type)
	}

	err = decode(rawConfig.Config, &factory)
	if err != nil {
		return err
	}

	c.Config = factory

	return nil
}

// AuthenticatorFactory creates a new auth.PasswordAuthenticator.
type AuthenticatorFactory interface {
	New() AuthenticatorFactory
	CreateAuthenticator() (auth.PasswordAuthenticator, error)
	Validate() error
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

func (c userAuthenticator) New() AuthenticatorFactory {
	return userAuthenticator{}
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

func (c userAuthenticator) Validate() error {
	for i, entry := range c.Entries {
		if entry.Username == "" {
			return fmt.Errorf("authenticator: user authenticator: entry[%d]: username is required", i)
		}

		if entry.PasswordHash == "" {
			return fmt.Errorf("authenticator: user authenticator: entry[%d]: password hash is required", i)
		}
	}

	return nil
}
