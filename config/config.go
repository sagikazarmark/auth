package config

// Config collects all configuration options.
type Config struct {
	Authenticator      Authenticator      `yaml:"authenticator"`
	AccessTokenIssuer  AccessTokenIssuer  `yaml:"accessTokenIssuer"`
	RefreshTokenIssuer RefreshTokenIssuer `yaml:"refreshTokenIssuer"`
	Authorizer         Authorizer         `yaml:"authorizer"`
}

// rawConfig is a general struct to be used by other config structs to unmarshal yaml config first.
type rawConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config"`
}
