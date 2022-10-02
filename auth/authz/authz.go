package authz

import (
	"context"
	"fmt"
	"strings"

	optionlib "github.com/sagikazarmark/go-option"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/pkg/option"
)

// DefaultAuthorizer implements a basic set of authorization rules
// and delegates authorization for repository resources.
// Access to everything else is denied.
type DefaultAuthorizer struct {
	repoAuthorizer RepositoryAuthorizer
	allowAnonymous bool
}

// RepositoryAuthorizer authorizes access requests to a specific repository.
type RepositoryAuthorizer interface {
	Authorize(ctx context.Context, name string, subject option.Option[auth.Subject], requestedActions []string) ([]string, error)
}

// NewDefaultAuthorizer returns a new DefaultAuthorizer.
func NewDefaultAuthorizer(repoAuthorizer RepositoryAuthorizer, allowAnonymous bool) DefaultAuthorizer {
	return DefaultAuthorizer{
		repoAuthorizer: repoAuthorizer,
		allowAnonymous: allowAnonymous,
	}
}

func (a DefaultAuthorizer) Authorize(ctx context.Context, subject option.Option[auth.Subject], requestedScopes []auth.Scope) ([]auth.Scope, error) {
	if !a.allowAnonymous && optionlib.IsNone[auth.Subject](subject) {
		return nil, auth.ErrUnauthorized
	}
	// Let's be optimistic about the amount of granted scopes
	grantedScopes := make([]auth.Scope, 0, len(requestedScopes))

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

func (a DefaultRepositoryAuthorizer) Authorize(_ context.Context, name string, optionalSubject option.Option[auth.Subject], requestedActions []string) ([]string, error) {
	if !a.allowAnonymous && optionlib.IsNone[auth.Subject](optionalSubject) {
		return nil, auth.ErrUnauthorized
	}

	subject := optionlib.Unwrap[auth.Subject](optionalSubject)

	if !strings.HasPrefix(name, fmt.Sprintf("%s/", subject.GetName())) {
		return []string{}, nil
	}

	return requestedActions, nil
}
