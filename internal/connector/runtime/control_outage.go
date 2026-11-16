package runtime

import (
	"context"

	"github.com/tnldotdev/tnl/internal/failure"
)

func temporaryOwnerRenewal(err error) bool {
	switch err := err.(type) {
	case interface{ Unwrap() []error }:
		causes := err.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !temporaryOwnerRenewal(cause) {
				return false
			}
		}
		return true
	case *failure.Error:
		return err.Reason() == failure.ServerUnavailable || err.Reason() == failure.ServerRateLimited
	case interface{ Unwrap() error }:
		return temporaryOwnerRenewal(err.Unwrap())
	default:
		return err == context.DeadlineExceeded
	}
}
