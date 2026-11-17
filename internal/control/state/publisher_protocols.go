package state

import (
	"slices"

	"github.com/tnldotdev/tnl/internal/config"
)

// publisherProtocols is a validated set of the existing protocol domain values,
// not a new protocol model. nil is reserved for non-exact grant roots.
type publisherProtocols []config.ProtocolName

func normalizePublisherProtocols(values []string) (publisherProtocols, error) {
	if len(values) == 0 || len(values) > 5 {
		return nil, ErrPublisherIdentity
	}
	result := make(publisherProtocols, len(values))
	for index, value := range values {
		protocol := config.ProtocolName(value)
		if !protocol.Valid() {
			return nil, ErrPublisherIdentity
		}
		result[index] = protocol
	}
	slices.Sort(result)
	if len(slices.Compact(slices.Clone(result))) != len(result) {
		return nil, ErrPublisherIdentity
	}
	return result, nil
}

func (p publisherProtocols) values() []string {
	if p == nil {
		return nil
	}
	values := make([]string, len(p))
	for index, protocol := range p {
		values[index] = string(protocol)
	}
	return values
}

func (p publisherProtocols) includes(protocol string) bool {
	return slices.Contains(p, config.ProtocolName(protocol))
}

func supportedPublisherProtocols() publisherProtocols {
	return publisherProtocols{
		config.ProtocolHTTP, config.ProtocolKubernetes, config.ProtocolMySQL,
		config.ProtocolPostgres, config.ProtocolTCP,
	}
}

// issuance captures the current editor's approved set once. service edits and
// later role changes cannot reconstruct or widen the persisted delegation.
func authorizePublisherProtocols(requested []string, administrator bool, protocol string) (publisherProtocols, error) {
	if requested == nil {
		if administrator {
			return supportedPublisherProtocols(), nil
		}
		requested = []string{string(config.ProtocolHTTP)}
	}
	approved, err := normalizePublisherProtocols(requested)
	if err != nil {
		return nil, err
	}
	if !administrator && (protocol != string(config.ProtocolHTTP) ||
		len(approved) != 1 || approved[0] != config.ProtocolHTTP) {
		return nil, ErrPublisherIdentity
	}
	return approved, nil
}
