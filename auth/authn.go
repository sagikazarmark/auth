package auth

import (
	"context"
	"errors"
)

// Attribute keys
const (
	// SubjectName is an attribute key for Subject providing an alternate name.
	SubjectName = "name"

	// SubjectType gives an Authorizer the ability to make authorization decisions based on an arbitrary classification of a Subject.
	// For example: users may have their own personal workspace to push to, machine users (commonly known as service account) may not.
	SubjectType = "type"
)

// Subject represents information about the authenticated subject.
type Subject struct {
	// ID is the primary identifier for the Subject (a username or an arbitrary ID (eg. UUID)),
	// but it is not necessarily globally unique: authentication can federate between various providers and/or subject types (eg. human vs machine users).
	// Therefore, the ID alone SHOULD NOT be used as a reference to the Subject.
	// The amount of information necessary to compose a key is an implementation/configuration detail,
	// but the ID, the type of subject (if any) and the provider (if any) are generally enough to compose a globally (ie. across all providers) unique key.
	//
	// The only place where ID shows up as a reference is the "sub" claim of JWTs issued as access tokens.
	ID string

	// Attributes are arbitrary key-value pairs that helps an Authorizer to make authorization decisions.
	// A common example attribute is "name" (SubjectName) that can provide an alternate name when the ID is an obscure identifier.
	Attributes map[string]string
}

// GetName helps determining a human-readable name for the Subject.
// It returns the attribute stored under the key "name" (SubjectName), if any.
// Otherwise it returns Subject.ID.
//
// A common use case for a friendly name is allowing an Authorizer to grant push access to a personal namespace.
func (s Subject) GetName() string {
	name, ok := s.Attributes[SubjectName]
	if !ok || name == "" {
		return s.ID
	}

	return name
}

// ErrAuthenticationFailed is returned when authentication fails.
//
// This error should only be returned if credential verification fails.
// Any other error (eg. connection problems) should be returned directly.
var ErrAuthenticationFailed = errors.New("authentication failed")

// PasswordAuthenticator authenticates a subject using the "password" grant or basic auth.
//
// It returns an ErrAuthenticationFailed error in case credentials are invalid.
type PasswordAuthenticator interface {
	Authenticate(ctx context.Context, username string, password string) (Subject, error)
}
