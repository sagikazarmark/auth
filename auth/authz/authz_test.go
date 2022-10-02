package authz

import (
	"context"
	"testing"

	optionlib "github.com/sagikazarmark/go-option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/distribution-auth/auth/auth"
	"github.com/distribution-auth/auth/pkg/option"
)

type repositoryAuthorizerStub struct {
	repositories map[string]bool
}

func (a repositoryAuthorizerStub) Authorize(_ context.Context, name string, subject option.Option[auth.Subject], actions []string) ([]string, error) {
	if !a.repositories[name] {
		return []string{}, nil
	}

	return actions, nil
}

func TestDefaultAuthorizer(t *testing.T) {
	subject := optionlib.Some(auth.Subject{
		ID: "user",
	})

	testCases := []struct {
		subject        option.Option[auth.Subject]
		scopes         []auth.Scope
		expectedScopes []auth.Scope
	}{
		{
			subject: subject,
			scopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "registry",
						Name: "catalog",
					},
					Actions: []string{"search"},
				},
			},
			expectedScopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "registry",
						Name: "catalog",
					},
					Actions: []string{"search"},
				},
			},
		},
		{
			subject: subject,
			scopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "user/repository",
					},
					Actions: []string{"push", "pull"},
				},
			},
			expectedScopes: []auth.Scope{
				{
					Resource: auth.Resource{
						Type: "repository",
						Name: "user/repository",
					},
					Actions: []string{"push", "pull"},
				},
			},
		},
	}

	authorizer := NewDefaultAuthorizer(
		repositoryAuthorizerStub{
			repositories: map[string]bool{
				"user/repository": true,
			},
		},
		false,
	)

	for _, testCase := range testCases {
		testCase := testCase

		t.Run("", func(t *testing.T) {
			grantedScopes, err := authorizer.Authorize(context.Background(), testCase.subject, testCase.scopes)
			require.NoError(t, err)

			assert.Equal(t, testCase.expectedScopes, grantedScopes)
		})
	}
}
