package auth

import (
	"time"
)

// AccessToken is a credential issued to a registry client described in the [AccessToken Authentication Specification].
//
// [AccessToken Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type AccessToken struct {
	Payload string

	ExpiresIn time.Duration
	IssuedAt  time.Time
}

// AccessTokenIssuer issues a token described in the [Token Authentication Specification].
//
// [Token Authentication Specification]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
type AccessTokenIssuer interface {
	IssueAccessToken(subject Subject, audience []string, grantedScopes []Scope) (AccessToken, error)
}
