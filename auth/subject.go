package auth

// Attribute keys
const (
	// SubjectName is an attribute key for Subject providing an alternate name.
	SubjectName = "name"

	// SubjectType is an arbitrary classification of a Subject that an Authorizer can base authorization decisions on.
	// For example: users may have their own personal workspace to push to, machine users (commonly known as service account) may not.
	// SubjectType can also serve as a component for a composite key that uniquely identifies a Subject.
	SubjectType = "type"
)

// Subject contains information about the authenticated subject.
// For most (authorization) use cases, the methods provided by Subject should be enough.
// However, custom implementations may provide additional behavior to help authorization decisions.
// That being said, it's up to the implementation to make sure all authenticators are able to return custom subject implementations.
type Subject interface {
	// ID is the primary identifier for the Subject (a username or an arbitrary ID (eg. UUID)),
	// but it is not necessarily globally unique: authentication can federate between various providers and/or subject types (eg. human vs machine users).
	// Therefore, the ID alone SHOULD NOT be used as a reference to the Subject.
	// The amount of information necessary to compose a key is an implementation/configuration detail,
	// but the ID, the type of subject (if any) and the provider (if any) are generally enough to compose a globally (ie. across all providers) unique key.
	//
	// The only place where ID shows up as a reference is the "sub" claim of JWTs issued as access tokens.
	ID() string

	// Attribute returns an attribute value and a boolean flag that shows whether the value exists or not.
	Attribute(key string) (string, bool)

	// Attributes are arbitrary key-value pairs that helps an Authorizer to make authorization decisions.
	//
	// Attributes MAY returns a copy of it's internal map to avoid modifications.
	// As a result, it MAY BE a relatively expensive operation and SHOULD only be used when necessary.
	// Prefer using Attribute instead.
	Attributes() map[string]string
}

// GetSubjectName helps determining a human-readable name for a Subject.
// It returns the attribute stored under the key "name" (SubjectName), if any.
// Otherwise it returns Subject.ID.
//
// A common use case for a friendly name is allowing an Authorizer to grant push access to a personal namespace.
func GetSubjectName(subject Subject) string {
	// TODO: add subjectNamer interface?
	name, ok := subject.Attribute(SubjectName)
	if !ok || name == "" {
		return subject.ID()
	}

	return name
}
