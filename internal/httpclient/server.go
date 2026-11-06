package httpclient

import (
	"errors"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

// CanonicalServer validates an HTTP client's control origin without depending on
// native credential persistence. naming owns URL rules; this owner adds diagnostics.
func CanonicalServer(value string) (string, error) {
	server, err := naming.CanonicalControlURL(value)
	if errors.Is(err, naming.ErrInvalidControlPort) {
		return "", failure.Wrap("validate control URL port", failure.InvalidControlPort, err)
	}
	if err != nil {
		return "", failure.Wrap("validate control URL", failure.InvalidControlURL, err)
	}
	return server, nil
}
