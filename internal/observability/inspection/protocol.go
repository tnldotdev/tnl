package inspection

// Protocol names the protocols with body-free inspection summaries. it is
// independent of the protocols supported by public URLs or private services.
type Protocol string

const (
	HTTP     Protocol = "http"
	Postgres Protocol = "postgres"
	MySQL    Protocol = "mysql"
	Redis    Protocol = "redis"
)

func ParseProtocol(value string) (Protocol, bool) {
	protocol := Protocol(value)
	return protocol, protocol.Valid()
}

func (p Protocol) Valid() bool {
	return p == HTTP || p.IsTCP()
}

func (p Protocol) IsSQL() bool { return p == Postgres || p == MySQL }

func (p Protocol) IsTCP() bool { return p.IsSQL() || p == Redis }
