package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	optionlib "github.com/sagikazarmark/go-option"

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

// DefaultAuthorizer implements a basic set of authorization rules
// and delegates authorization for repository resources.
// Access to everything else is denied.
type DefaultAuthorizer struct {
	repoAuthorizer RepositoryAuthorizer
	allowAnonymous bool
}

// RepositoryAuthorizer authorizes access requests to a specific repository.
type RepositoryAuthorizer interface {
	Authorize(ctx context.Context, name string, subject option.Option[Subject], requestedActions []string) ([]string, error)
}

// NewDefaultAuthorizer returns a new DefaultAuthorizer.
func NewDefaultAuthorizer(repoAuthorizer RepositoryAuthorizer, allowAnonymous bool) DefaultAuthorizer {
	return DefaultAuthorizer{
		repoAuthorizer: repoAuthorizer,
		allowAnonymous: allowAnonymous,
	}
}

func (a DefaultAuthorizer) Authorize(ctx context.Context, subject option.Option[Subject], requestedScopes []Scope) ([]Scope, error) {
	if !a.allowAnonymous && optionlib.IsNone[Subject](subject) {
		return nil, ErrUnauthorized
	}
	// Let's be optimistic about the amount of granted scopes
	grantedScopes := make([]Scope, 0, len(requestedScopes))

	for _, scope := range requestedScopes {
		if scope.Type == "repository" {
			grantedActions, err := a.repoAuthorizer.Authorize(ctx, scope.Name, subject, scope.Actions)
			if err != nil {
				// TODO: collect errors?
				return nil, err
			}

			// Don't add a scope with no actions
			if len(grantedActions) == 0 {
				continue
			}

			scope.Actions = grantedActions
		} else if scope.Type == "registry" {
			// TODO: Limit some actions to "admin" users
			if scope.Name != "catalog" {
				// TODO: log: unknown registry resource
				continue
			}
		} else {
			// TODO: log: unsupported resource type
			continue
		}

		grantedScopes = append(grantedScopes, scope)
	}

	return grantedScopes, nil
}

// DefaultRepositoryAuthorizer implements a simple authorization logic for authenticated users.
type DefaultRepositoryAuthorizer struct {
	allowAnonymous bool
}

// NewDefaultRepositoryAuthorizer returns a new DefaultRepositoryAuthorizer.
func NewDefaultRepositoryAuthorizer(allowAnonymous bool) DefaultRepositoryAuthorizer {
	return DefaultRepositoryAuthorizer{
		allowAnonymous: allowAnonymous,
	}
}

func (a DefaultRepositoryAuthorizer) Authorize(_ context.Context, name string, optionalSubject option.Option[Subject], requestedActions []string) ([]string, error) {
	if !a.allowAnonymous && optionlib.IsNone[Subject](optionalSubject) {
		return nil, ErrUnauthorized
	}

	subject := optionlib.Unwrap[Subject](optionalSubject)

	if !strings.HasPrefix(name, fmt.Sprintf("%s/", subject.GetName())) {
		return []string{}, nil
	}

	return requestedActions, nil
}
