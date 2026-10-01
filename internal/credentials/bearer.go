package credentials

import (
	"errors"
	"net/http"
	"strings"
)

var ErrInvalidAuthorization = errors.New("invalid authorization header")

// Bearer extracts one opaque token from exactly one Authorization header. the
// scheme is case-insensitive; whitespace and comma-combined tokens are rejected.
// it does not validate a credential class or authenticate its holder.
func Bearer(headers http.Header) (string, error) {
	values := headers.Values("Authorization")
	if len(values) != 1 {
		return "", ErrInvalidAuthorization
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n,") {
		return "", ErrInvalidAuthorization
	}
	return token, nil
}
