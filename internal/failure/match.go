package failure

import "errors"

// Only reports whether every leaf cause matches target. unlike errors.Is, a
// matching cancellation cannot hide an independent failure in a joined error.
func Only(err, target error) bool {
	if err == nil {
		return target == nil
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
