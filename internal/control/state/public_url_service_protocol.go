package state

import "github.com/tnldotdev/tnl/internal/policy/authorization"

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
	if !protocol.Valid() || !purpose.ValidForCreation() {
		return false
	}
	if purpose == PublicURLPurposeOAuth || purpose == PublicURLPurposeWebhooks {
		return target == "" && !ephemeral
	}
	if target == "" {
		return !ephemeral && (purpose == PublicURLPurposeApp || purpose == PublicURLPurposeAlias)
	}
	return authorization.ValidateTarget(target) == nil
}
