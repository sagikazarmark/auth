package config

import "fmt"

// Config collects all configuration options.
type Config struct {
	Authenticator      Authenticator      `yaml:"authenticator"`
	AccessTokenIssuer  AccessTokenIssuer  `yaml:"accessTokenIssuer"`
	RefreshTokenIssuer RefreshTokenIssuer `yaml:"refreshTokenIssuer"`
	Authorizer         Authorizer         `yaml:"authorizer"`
}

// Validate validates the configuration.
func (c Config) Validate() error {
	if c.Authenticator.Type == "" {
		return fmt.Errorf("authenticator type is required")
	}

	if err := c.Authenticator.Config.Validate(); err != nil {
		return err
	}

	if c.AccessTokenIssuer.Type == "" {
		return fmt.Errorf("access token issuer type is required")
	}

	if err := c.AccessTokenIssuer.Config.Validate(); err != nil {
		return err
	}

	if c.RefreshTokenIssuer.Type == "" {
		return fmt.Errorf("refresh token issuer type is required")
	}

	if err := c.RefreshTokenIssuer.Config.Validate(); err != nil {
		return err
	}

	if c.Authorizer.Type == "" {
		return fmt.Errorf("authorizer type is required")
	}

	if err := c.Authorizer.Config.Validate(); err != nil {
		return err
	}

	return nil
}

// rawConfig is a general struct to be used by other config structs to unmarshal yaml config first.
type rawConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config"`
}
