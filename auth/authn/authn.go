package authn

import (
	"context"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/maps"

	"github.com/distribution-auth/auth/auth"
)

type subject struct {
	id         string
	attributes map[string]string
}

func (s subject) ID() string {
	return s.id
}

func (s subject) Attribute(key string) (string, bool) {
	if s.attributes == nil {
		return "", false
	}

	v, ok := s.attributes[key]

	return v, ok
}

func (s subject) Attributes() map[string]string {
	return maps.Clone(s.attributes)
}

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

		return nil, auth.ErrAuthenticationFailed
	}

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return nil, auth.ErrAuthenticationFailed
	}

	return subject{
		id: username,
	}, nil
}
