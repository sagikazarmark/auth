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
	passwordAuthenticatorFactoriesMu sync.RWMutex
	passwordAuthenticatorFactories   = make(map[string]PasswordAuthenticatorFactory)
)

// RegisterPasswordAuthenticatorFactory makes an AuthenticatorFactory available by the provided name in configuration.
//
// If RegisterPasswordAuthenticatorFactory is called twice with the same name or if factory is nil,
// it panics.
func RegisterPasswordAuthenticatorFactory(name string, factory PasswordAuthenticatorFactory) {
	passwordAuthenticatorFactoriesMu.Lock()
	defer passwordAuthenticatorFactoriesMu.Unlock()

	if factory == nil {
		panic("registering password authenticator factory: factory is nil")
	}

	if _, dup := passwordAuthenticatorFactories[name]; dup {
		panic("registering password authenticator factory: registration called twice for factory " + name)
	}

	passwordAuthenticatorFactories[name] = factory
}

func init() {
	RegisterPasswordAuthenticatorFactory("user", userAuthenticator{})
}

// PasswordAuthenticator is the configuration for an auth.PasswordAuthenticator.
type PasswordAuthenticator struct {
	Config PasswordAuthenticatorFactory
}

func (c *PasswordAuthenticator) UnmarshalYAML(value *yaml.Node) error {
	var rawConfig rawConfig

	err := value.Decode(&rawConfig)
	if err != nil {
		return err
	}

	passwordAuthenticatorFactoriesMu.RLock()
	factory, ok := passwordAuthenticatorFactories[rawConfig.Type]
	passwordAuthenticatorFactoriesMu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown password authenticator type: %s", rawConfig.Type)
	}

	err = decode(rawConfig.Config, &factory)
	if err != nil {
		return err
	}

	c.Config = factory

	return nil
}

// PasswordAuthenticatorFactory creates a new auth.PasswordAuthenticator.
type PasswordAuthenticatorFactory interface {
	New() PasswordAuthenticatorFactory
	CreatePasswordAuthenticator() (auth.PasswordAuthenticator, error)
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

func (c userAuthenticator) New() PasswordAuthenticatorFactory {
	return userAuthenticator{}
}

func (c userAuthenticator) CreatePasswordAuthenticator() (auth.PasswordAuthenticator, error) {
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
			return fmt.Errorf("password authenticator: user authenticator: entry[%d]: username is required", i)
		}

		if entry.PasswordHash == "" {
			return fmt.Errorf("password authenticator: user authenticator: entry[%d]: password hash is required", i)
		}
	}

	return nil
}
