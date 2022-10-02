package authn

import (
	"context"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/maps"

	"github.com/distribution-auth/auth/auth"
)

// StaticPasswordAuthenticator authenticates a subject from a static list of users.
type StaticPasswordAuthenticator struct {
	users map[string]string
}

// NewStaticPasswordAuthenticator returns a new StaticPasswordAuthenticator.
func NewStaticPasswordAuthenticator(users map[string]string) StaticPasswordAuthenticator {
	return StaticPasswordAuthenticator{
		users: maps.Clone(users),
	}
}

// Authenticate implements the PasswordAuthenticator interface.
func (a StaticPasswordAuthenticator) Authenticate(_ context.Context, username string, password string) (auth.Subject, error) {
	passwordHash, ok := a.users[username]
	if !ok {
		// timing attack paranoia
		bcrypt.CompareHashAndPassword([]byte{}, []byte(password))

		return auth.Subject{}, auth.ErrAuthenticationFailed
	}

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return auth.Subject{}, auth.ErrAuthenticationFailed
	}

	return auth.Subject{
		ID: username,
	}, nil
}
