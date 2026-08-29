package credentials

import (
	"errors"
	"net/http"
	"strings"
)

var ErrInvalidAuthorization = errors.New("invalid authorization header")

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
