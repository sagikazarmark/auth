package auth

import (
	"context"
	"time"

	"go.uber.org/zap"
)

type TokenService interface {
	// TokenHandler implements the [Docker Registry v2 authentication] specification.
	//
	// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
	TokenHandler(ctx context.Context, r TokenRequest) (TokenResponse, error)

	// OAuth2Handler implements the [Docker Registry v2 OAuth2 authentication] specification.
	//
	// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
	OAuth2Handler(ctx context.Context, r OAuth2Request) (OAuth2Response, error)
}

type TokenRequest struct {
	Service  string
	ClientID string
	Offline  bool
	Scopes   Scopes

	Anonymous bool
	Username  string
	Password  string
}

type TokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

type OAuth2Request struct {
	GrantType string

	Service    string
	ClientID   string
	AccessType string
	Scopes     Scopes

	Username     string
	Password     string
	RefreshToken string
}

type OAuth2Response struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Authenticator is a facade combining different type of authenticators.
type Authenticator struct {
	PasswordAuthenticator
	RefreshTokenAuthenticator
}

// TokenIssuer is a facade combining different type of token issuers.
type TokenIssuer struct {
	AccessTokenIssuer
	RefreshTokenIssuer
}

// TokenServer implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/index.md
type TokenServiceImpl struct {
	Authenticator Authenticator
	Authorizer    Authorizer
	TokenIssuer   TokenIssuer

	Logger *zap.Logger
}

// TokenHandler implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
func (s TokenServiceImpl) TokenHandler(ctx context.Context, r TokenRequest) (TokenResponse, error) {
	var subject Subject

	if !r.Anonymous {
		var err error

		subject, err = s.Authenticator.AuthenticatePassword(ctx, r.Username, r.Password)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	// TODO: handle missing service value
	// TODO: missing client_id

	grantedScopes, err := s.Authorizer.Authorize(ctx, subject, r.Scopes)
	if err != nil {
		return TokenResponse{}, err
	}

	token, err := s.TokenIssuer.IssueAccessToken(ctx, r.Service, subject, grantedScopes)
	if err != nil {
		return TokenResponse{}, err
	}

	s.Logger.Debug("client authorized")

	response := TokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
	}

	if r.Offline && subject != nil {
		refreshToken, err := s.TokenIssuer.IssueRefreshToken(ctx, r.Service, subject)
		if err != nil {
			return TokenResponse{}, err
		}

		response.RefreshToken = refreshToken
	}

	return response, nil
}

func (s TokenServiceImpl) OAuth2Handler(ctx context.Context, r OAuth2Request) (OAuth2Response, error) {
	// TODO: OAuth2 error: missing grant_type value
	// TODO: OAuth2 error: missing service value
	// TODO: OAuth2 error: missing client_id value
	// TODO: OAuth2 error: unknown access_type value

	var subject Subject
	var refreshToken string

	switch r.GrantType {
	case "refresh_token":
		refreshToken = r.RefreshToken
		if refreshToken == "" {
			// TODO: OAuth2 error: missing refresh_token value
			return OAuth2Response{}, nil
		}

		var err error

		subject, err = s.Authenticator.AuthenticateRefreshToken(ctx, r.Service, refreshToken)
		if err != nil {
			return OAuth2Response{}, err
		}

		// TODO: check if service is the same as stored in the refresh token
	case "password":
		username := r.Username
		if username == "" {
			// TODO: OAuth2 error: missing username value
			return OAuth2Response{}, nil
		}
		password := r.Password
		if password == "" {
			// TODO: OAuth2 error: missing password value
			return OAuth2Response{}, nil
		}

		var err error

		subject, err = s.Authenticator.AuthenticatePassword(ctx, username, password)
		if err != nil {
			return OAuth2Response{}, err
		}
	default:
		// TODO: OAuth2 error: unknown grant_type value
		return OAuth2Response{}, nil
	}

	grantedScopes, err := s.Authorizer.Authorize(ctx, subject, r.Scopes)
	if err != nil {
		return OAuth2Response{}, err
	}

	token, err := s.TokenIssuer.IssueAccessToken(ctx, r.Service, subject, grantedScopes)
	if err != nil {
		return OAuth2Response{}, err
	}

	s.Logger.Debug("client authorized")

	response := OAuth2Response{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
		IssuedAt:  token.IssuedAt.Format(time.RFC3339),
		Scope:     Scopes(grantedScopes).String(),
	}

	if r.AccessType == "offline" && subject != nil && r.GrantType == "refresh_token" {
		token, err := s.TokenIssuer.IssueRefreshToken(ctx, r.Service, subject)
		if err != nil {
			return OAuth2Response{}, err
		}

		refreshToken = token
	}

	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	return response, nil
}
