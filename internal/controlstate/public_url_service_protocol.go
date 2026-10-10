package controlstate

// PublicURLServiceProtocol selects the visitor handshake at the publisher.
type PublicURLServiceProtocol string

const (
	PublicURLServiceHTTP     PublicURLServiceProtocol = "http"
	PublicURLServicePostgres PublicURLServiceProtocol = "postgres"
	PublicURLServiceMySQL    PublicURLServiceProtocol = "mysql"
)

func (protocol PublicURLServiceProtocol) Valid() bool {
	return protocol == PublicURLServiceHTTP || protocol == PublicURLServicePostgres || protocol == PublicURLServiceMySQL
}
