package config

// Config collects all configuration options.
type Config struct {
	PasswordAuthenticator PasswordAuthenticator `yaml:"passwordAuthenticator"`
	AccessTokenIssuer     AccessTokenIssuer     `yaml:"accessTokenIssuer"`
	RefreshTokenIssuer    RefreshTokenIssuer    `yaml:"refreshTokenIssuer"`
	Authorizer            Authorizer            `yaml:"authorizer"`
}

// Validate validates the configuration.
//
//nolint
func (c Config) Validate() error {
	if err := c.PasswordAuthenticator.Validate(); err != nil {
		return err
	}

	if err := c.AccessTokenIssuer.Validate(); err != nil {
		return err
	}

	if err := c.RefreshTokenIssuer.Validate(); err != nil {
		return err
	}

	if err := c.Authorizer.Validate(); err != nil {
		return err
	}

	return nil
}

// rawConfig is a general struct to be used by other config structs to unmarshal yaml config first.
type rawConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config"`
}
