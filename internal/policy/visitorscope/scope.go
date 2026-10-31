// package visitorscope names the exact resource authorized by a visitor permission.
package visitorscope

import "github.com/tnldotdev/tnl/internal/naming/opaqueid"

type Kind string

const (
	PublicURL Kind = "public_url"
	Service   Kind = "service"
)

// Scope never infers resource identity from a hostname or a certificate.
type Scope struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
}

func (s Scope) Valid() bool {
	switch s.Kind {
	case PublicURL:
		return opaqueid.Valid(s.ID, opaqueid.PublicURLPrefix)
	case Service:
		return opaqueid.Valid(s.ID, opaqueid.ServicePrefix)
	default:
		return false
	}
}
