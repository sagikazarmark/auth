package auth

import (
	"time"

	"github.com/distribution-auth/auth/pkg/option"
)

// Token is a credential issued to a registry client described in the [Token Authentication Specification].
//
// [Token Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type Token struct {
	Payload string

	ExpiresIn time.Duration
	IssuedAt  time.Time
}

// TokenIssuer issues a token described in the [Token Authentication Specification].
//
// [Token Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type TokenIssuer interface {
	IssueToken(subject option.Option[Subject], audience []string, grantedScopes []Scope) (Token, error)
}
