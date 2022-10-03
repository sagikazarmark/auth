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
	OAuth2TokenHandler(ctx context.Context, r OAuth2TokenRequest) (OAuth2TokenResponse, error)
}

type TokenRequest struct {
	Service  string   `schema:"service"`
	ClientID string   `schema:"client_id"`
	Offline  bool     `schema:"offline_token"`
	Scope    []string `schema:"scope"`

	Anonymous bool   `schema:"-"`
	Username  string `schema:"-"`
	Password  string `schema:"-"`
}

type TokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

type OAuth2TokenRequest struct {
	GrantType string `schema:"grant_type"`

	Service    string   `schema:"service"`
	ClientID   string   `schema:"client_id"`
	AccessType string   `schema:"access_type"`
	Scope      []string `schema:"scope"`

	Username     string `schema:"username"`
	Password     string `schema:"password"`
	RefreshToken string `schema:"refresh_token"`
}

type OAuth2TokenResponse struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenServer implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/index.md
type TokenServiceImpl struct {
	Authenticator             PasswordAuthenticator
	Authorizer                Authorizer
	AccessTokenIssuer         AccessTokenIssuer
	RefreshTokenAuthenticator RefreshTokenAuthenticator
	RefreshTokenIssuer        RefreshTokenIssuer

	Logger *zap.Logger
}

// TokenHandler implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
func (s TokenServiceImpl) TokenHandler(ctx context.Context, r TokenRequest) (TokenResponse, error) {
	var subject Subject

	if !r.Anonymous {
		var err error

		subject, err = s.Authenticator.Authenticate(ctx, r.Username, r.Password)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	// TODO: handle missing service value
	// TODO: missing client_id

	requestedScopes, err := ParseScopes(r.Scope)
	if err != nil {
		return TokenResponse{}, err
	}

	grantedScopes, err := s.Authorizer.Authorize(ctx, subject, requestedScopes)
	if err != nil {
		return TokenResponse{}, err
	}

	token, err := s.AccessTokenIssuer.IssueAccessToken(subject, []string{r.Service}, grantedScopes)
	if err != nil {
		return TokenResponse{}, err
	}

	s.Logger.Debug("client authorized")

	response := TokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
	}

	if r.Offline && subject != nil {
		refreshToken, err := s.RefreshTokenIssuer.IssueRefreshToken(ctx, subject)
		if err != nil {
			return TokenResponse{}, err
		}

		response.RefreshToken = refreshToken
	}

	return response, nil
}

func (s TokenServiceImpl) OAuth2TokenHandler(ctx context.Context, r OAuth2TokenRequest) (OAuth2TokenResponse, error) {
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
			return OAuth2TokenResponse{}, nil
		}

		var err error

		subject, err = s.RefreshTokenAuthenticator.Authenticate(ctx, refreshToken)
		if err != nil {
			return OAuth2TokenResponse{}, err
		}

		// TODO: check if service is the same as stored in the refresh token
	case "password":
		username := r.Username
		if username == "" {
			// TODO: OAuth2 error: missing username value
			return OAuth2TokenResponse{}, nil
		}
		password := r.Password
		if password == "" {
			// TODO: OAuth2 error: missing password value
			return OAuth2TokenResponse{}, nil
		}

		var err error

		subject, err = s.Authenticator.Authenticate(ctx, username, password)
		if err != nil {
			return OAuth2TokenResponse{}, err
		}
	default:
		// TODO: OAuth2 error: unknown grant_type value
		return OAuth2TokenResponse{}, nil
	}

	requestedScopes, err := ParseScopes(r.Scope)
	if err != nil {
		return OAuth2TokenResponse{}, err
	}

	grantedScopes, err := s.Authorizer.Authorize(ctx, subject, requestedScopes)
	if err != nil {
		return OAuth2TokenResponse{}, err
	}

	token, err := s.AccessTokenIssuer.IssueAccessToken(subject, []string{r.Service}, grantedScopes)
	if err != nil {
		return OAuth2TokenResponse{}, err
	}

	s.Logger.Debug("client authorized")

	response := OAuth2TokenResponse{
		Token:     token.Payload,
		ExpiresIn: int(token.ExpiresIn.Seconds()),
		IssuedAt:  token.IssuedAt.Format(time.RFC3339),
		Scope:     Scopes(grantedScopes).String(),
	}

	if r.AccessType == "offline" && subject != nil && r.GrantType == "refresh_token" {
		token, err := s.RefreshTokenIssuer.IssueRefreshToken(ctx, subject)
		if err != nil {
			return OAuth2TokenResponse{}, err
		}

		refreshToken = token
	}

	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	return response, nil
}
