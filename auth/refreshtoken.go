package auth

import (
	"context"
)

// RefreshTokenIssuer issues a token that a client can use to issue a new token for a subject without presenting credentials again.
// TODO: add service as a parameter.
type RefreshTokenIssuer interface {
	IssueRefreshToken(ctx context.Context, subject Subject) (string, error)
}

// RefreshTokenAuthenticator authenticates a refresh token.
// TODO: add service as a parameter.
type RefreshTokenAuthenticator interface {
	Authenticate(ctx context.Context, refreshToken string) (Subject, error)
}
