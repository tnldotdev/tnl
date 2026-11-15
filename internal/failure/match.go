package failure

import (
	"errors"
	"reflect"
)

// Only reports whether each cause chain reaches target. unlike errors.Is, a
// matching cancellation cannot hide an independent failure in a joined error.
func Only(err, target error) bool {
	if err == nil {
		return target == nil
	}
	if target != nil && reflect.TypeOf(target).Comparable() && err == target {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !Only(child, target) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return Only(wrapped, target)
	}
	return errors.Is(err, target)
}
