package controlstate

import "github.com/tnldotdev/tnl/internal/authorization"

// PublicURLServiceProtocol selects the visitor handshake at the publisher.
type PublicURLServiceProtocol string

const (
	PublicURLServiceHTTP PublicURLServiceProtocol = "http"
	PublicURLServiceTCP  PublicURLServiceProtocol = "tcp"
	PublicURLServiceSSH  PublicURLServiceProtocol = "ssh"
)

func (protocol PublicURLServiceProtocol) Valid() bool {
	return protocol == PublicURLServiceHTTP || protocol == PublicURLServiceTCP || protocol == PublicURLServiceSSH
}

// ValidCreateTarget checks how a public URL receives its local target.
func (protocol PublicURLServiceProtocol) ValidCreateTarget(purpose PublicURLPurpose, target string, ephemeral bool) bool {
	if !protocol.Valid() || protocol != PublicURLServiceHTTP && (purpose != PublicURLPurposeApp || target != "") ||
		target == "" && (purpose != PublicURLPurposeApp || ephemeral && protocol == PublicURLServiceHTTP) {
		return false
	}
	return target == "" || authorization.ValidateTarget(target) == nil
}
