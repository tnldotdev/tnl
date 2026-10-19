package config

// ProtocolName identifies service behavior independently of public or private
// publication. public HTTPS accepts only ProtocolHTTP.
type ProtocolName string

const (
	ProtocolHTTP     ProtocolName = "http"
	ProtocolTCP      ProtocolName = "tcp"
	ProtocolMySQL    ProtocolName = "mysql"
	ProtocolPostgres ProtocolName = "postgres"
)

func (p ProtocolName) Valid() bool { return ValidProtocol(string(p)) }
