package authn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/distribution-auth/auth/auth"
)

func TestStaticPasswordAuthenticator(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		const (
			username = "user"
			password = "password"
		)
		expectedSubject := subject{
			id: "user",
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
		require.NoError(t, err)

		authenticator := NewStaticPasswordAuthenticator(map[string]string{
			username: string(passwordHash),
		})

		subject, err := authenticator.Authenticate(context.Background(), username, password)
		require.NoError(t, err)

		assert.Equal(t, expectedSubject, subject)
	})

	t.Run("Error", func(t *testing.T) {
		authenticator := NewStaticPasswordAuthenticator(map[string]string{})

		_, err := authenticator.Authenticate(context.Background(), "username", "password")
		require.Error(t, err)

		assert.Equal(t, auth.ErrAuthenticationFailed, err)
	})
}
