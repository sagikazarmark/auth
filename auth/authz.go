package auth

import (
	"context"
	"errors"

	"github.com/distribution-auth/auth/pkg/option"
)

// ErrUnauthorized is returned when a client did not provide any credentials
// and the authorization server does not support anonymous access.
// TODO: this could be moved to another component to make anonymous access check global.
var ErrUnauthorized = errors.New("unauthorized")

// Authorizer authorizes an access request to a list of resources (scopes) and returns the list of granted scopes.
type Authorizer interface {
	Authorize(ctx context.Context, subject option.Option[Subject], requestedScopes []Scope) ([]Scope, error)
}
