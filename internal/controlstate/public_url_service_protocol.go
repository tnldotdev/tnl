package controlstate

import "github.com/tnldotdev/tnl/internal/authorization"

// PublicURLServiceProtocol selects the visitor handshake at the publisher.
type PublicURLServiceProtocol string

const (
	PublicURLServiceHTTP     PublicURLServiceProtocol = "http"
	PublicURLServicePostgres PublicURLServiceProtocol = "postgres"
	PublicURLServiceMySQL    PublicURLServiceProtocol = "mysql"
	PublicURLServiceRedis    PublicURLServiceProtocol = "redis"
	PublicURLServiceSSH      PublicURLServiceProtocol = "ssh"
	PublicURLServiceMongoDB  PublicURLServiceProtocol = "mongodb"
)

func (protocol PublicURLServiceProtocol) Valid() bool {
	return protocol == PublicURLServiceHTTP || protocol == PublicURLServicePostgres || protocol == PublicURLServiceMySQL || protocol == PublicURLServiceRedis || protocol == PublicURLServiceSSH || protocol == PublicURLServiceMongoDB
}

// ValidCreateTarget checks how a public URL receives its local target.
func (protocol PublicURLServiceProtocol) ValidCreateTarget(purpose PublicURLPurpose, target string, ephemeral bool) bool {
	if !protocol.Valid() || protocol != PublicURLServiceHTTP && (purpose != PublicURLPurposeApp || target != "") ||
		target == "" && (purpose != PublicURLPurposeApp || ephemeral && protocol == PublicURLServiceHTTP) {
		return false
	}
	return target == "" || authorization.ValidateTarget(target) == nil
}
