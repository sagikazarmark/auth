package option

// Option represents an optional value.
// It either contains a value or it does not.
//
// This interface is odeled after github.com/sagikazarmark/go-option.Option
type Option[T any] interface {
	// HasValue returns true if the Option contains a value.
	HasValue() bool

	// Value returns the value (or its default) stored in the Option.
	Value() T
}
