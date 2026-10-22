// package httpsubject names the authorization boundary of an HTTP frontend.
package httpsubject

import "github.com/tnldotdev/tnl/internal/naming/opaqueid"

type Kind string

const (
	PublicURL      Kind = "public_url"
	ManagedService Kind = "managed_service"
)

// Subject never infers scope from a hostname or a certificate.
type Subject struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
}

func (s Subject) Valid() bool {
	switch s.Kind {
	case PublicURL:
		return opaqueid.Valid(s.ID, opaqueid.PublicURLPrefix)
	case ManagedService:
		return opaqueid.Valid(s.ID, opaqueid.PrivateServicePrefix)
	default:
		return false
	}
}
