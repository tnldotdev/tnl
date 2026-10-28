package tunnelv1

import (
	"errors"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const (
	MaxNativePeerCandidates        = 32
	MaxNativePeerConnectivityBytes = 32 << 10
)

var ErrNativePeerConnectivity = errors.New("native peer connectivity message is invalid")

// NativePeerConnectivity travels on a dedicated unidirectional stream for each
// attempt in each direction of the existing inner QUIC connection. it grants no
// application permission and carries no source-IP authority or renewable deadline.
type NativePeerConnectivity struct {
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

func (NativePeerConnectivity) String() string   { return "native peer connectivity" }
func (NativePeerConnectivity) GoString() string { return "native peer connectivity" }

func (m NativePeerConnectivity) Validate() error {
	if m.ProtocolVersion != Version || m.Kind != "native_peer_connectivity" || !opaqueid.Valid(m.PairID, "npp_") || m.DeliveryGeneration < 1 || m.Attempt == 0 {
		return ErrNativePeerConnectivity
	}
	if _, err := ParsePeerDeliveryIdentifier(m.DeliveryID); err != nil {
		return ErrNativePeerConnectivity
	}
	credential := func(value string, minimum int) bool {
		return len(value) >= minimum && len(value) <= 256 && strings.IndexFunc(value, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '/')
		}) == -1
	}
	if !credential(m.UsernameFragment, 4) || !credential(m.Password, 22) || len(m.Candidates) == 0 || len(m.Candidates) > MaxNativePeerCandidates {
		return ErrNativePeerConnectivity
	}
	for _, candidate := range m.Candidates {
		if len(candidate) == 0 || len(candidate) > 768 || strings.IndexFunc(candidate, func(r rune) bool { return r < 32 || r > 126 }) != -1 {
			return ErrNativePeerConnectivity
		}
	}
	return nil
}

func WriteNativePeerConnectivity(w io.Writer, m NativePeerConnectivity) error {
	if err := m.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, m, MaxNativePeerConnectivityBytes)
}

func ReadNativePeerConnectivity(r io.Reader) (NativePeerConnectivity, error) {
	var m NativePeerConnectivity
	if err := readJSONFrame(r, &m, MaxNativePeerConnectivityBytes); err != nil {
		return NativePeerConnectivity{}, errors.Join(ErrNativePeerConnectivity, err)
	}
	if err := m.Validate(); err != nil {
		return NativePeerConnectivity{}, err
	}
	return m, nil
}
