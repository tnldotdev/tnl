// package authorization holds current control authorization errors and IP rules.
package authorization

import "errors"

var (
	ErrInvalid         = errors.New("authorization: invalid request")
	ErrUnauthenticated = errors.New("authorization: unauthenticated")
	ErrForbidden       = errors.New("authorization: forbidden")
	ErrGuestDemoOnly   = errors.New("authorization: guest demo options require sign-in")
	ErrGuestIPChanged  = errors.New("authorization: guest demo source IP changed")
	ErrUnavailable     = errors.New("authorization: unavailable")
)
