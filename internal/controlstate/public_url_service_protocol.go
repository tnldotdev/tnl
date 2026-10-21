package controlstate

import "github.com/tnldotdev/tnl/internal/authorization"

// PublicURLServiceProtocol selects the visitor handshake at the publisher.
type PublicURLServiceProtocol string

const (
	PublicURLServiceHTTP PublicURLServiceProtocol = "http"
)

func (protocol PublicURLServiceProtocol) Valid() bool {
	return protocol == PublicURLServiceHTTP
}

// ValidCreateTarget checks how a public URL receives its local target.
func (protocol PublicURLServiceProtocol) ValidCreateTarget(purpose PublicURLPurpose, target string, ephemeral bool) bool {
	if !protocol.Valid() || !purpose.ValidForCreation() ||
		target == "" && (ephemeral || purpose != PublicURLPurposeApp && purpose != PublicURLPurposeAlias) {
		return false
	}
	return target == "" || authorization.ValidateTarget(target) == nil
}
