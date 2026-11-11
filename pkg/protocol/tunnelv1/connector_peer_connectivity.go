package tunnelv1

import (
	"errors"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const (
	MaxConnectorPeerCandidates        = 32
	MaxConnectorPeerConnectivityBytes = 32 << 10
)

var ErrConnectorPeerConnectivity = errors.New("connector peer connectivity message is invalid")

// ConnectorPeerConnectivity describes one offer or answer on the retained inner
// connection. its attempt number never resets on network rebinding. candidates
// and credentials are delivery hints, not source authority or visitor permission.
type ConnectorPeerConnectivity struct {
	ProtocolVersion    uint32   `json:"protocol_version"`
	Kind               string   `json:"kind"`
	PairID             string   `json:"pair_id"`
	DeliveryID         string   `json:"delivery_id"`
	DeliveryGeneration int64    `json:"delivery_generation"`
	Attempt            uint64   `json:"attempt"`
	UsernameFragment   string   `json:"username_fragment"`
	Password           string   `json:"password"`
	Candidates         []string `json:"candidates"`
}

func (ConnectorPeerConnectivity) String() string   { return "connector peer connectivity" }
func (ConnectorPeerConnectivity) GoString() string { return "connector peer connectivity" }

func (m ConnectorPeerConnectivity) Validate() error {
	if m.ProtocolVersion != Version || m.Kind != "connector_peer_connectivity" || !opaqueid.Valid(m.PairID, "cpp_") || m.DeliveryGeneration < 1 || m.Attempt == 0 {
		return ErrConnectorPeerConnectivity
	}
	if _, err := ParsePeerDeliveryIdentifier(m.DeliveryID); err != nil {
		return ErrConnectorPeerConnectivity
	}
	credential := func(value string, minimum int) bool {
		return len(value) >= minimum && len(value) <= 256 && strings.IndexFunc(value, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '/')
		}) == -1
	}
	if !credential(m.UsernameFragment, 4) || !credential(m.Password, 22) || len(m.Candidates) == 0 || len(m.Candidates) > MaxConnectorPeerCandidates {
		return ErrConnectorPeerConnectivity
	}
	for _, candidate := range m.Candidates {
		if len(candidate) == 0 || len(candidate) > 768 || strings.IndexFunc(candidate, func(r rune) bool { return r < 32 || r > 126 }) != -1 {
			return ErrConnectorPeerConnectivity
		}
	}
	return nil
}

func WriteConnectorPeerConnectivity(w io.Writer, m ConnectorPeerConnectivity) error {
	if err := m.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, m, MaxConnectorPeerConnectivityBytes)
}

func ReadConnectorPeerConnectivity(r io.Reader) (ConnectorPeerConnectivity, error) {
	var m ConnectorPeerConnectivity
	if err := readJSONFrame(r, &m, MaxConnectorPeerConnectivityBytes); err != nil {
		return ConnectorPeerConnectivity{}, errors.Join(ErrConnectorPeerConnectivity, err)
	}
	if err := m.Validate(); err != nil {
		return ConnectorPeerConnectivity{}, err
	}
	return m, nil
}
