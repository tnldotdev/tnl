package tunnelv1

import (
	"bytes"
	"errors"
)

// ConnectorLegBinding selects one authenticated carrier candidate by the nonce in
// its signed hello. it neither refreshes authority nor admits an application.
type ConnectorLegBinding struct {
	Nonce         []byte `json:"nonce"`
	PreviousNonce []byte `json:"previous_nonce,omitempty"`
	// replacement_nonce identifies one handoff across fresh hello attempts.
	ReplacementNonce []byte `json:"replacement_nonce,omitempty"`
}

var ErrConnectorLegBinding = errors.New("connector carrier binding is invalid")

func (b ConnectorLegBinding) Validate() error {
	if len(b.Nonce) != 32 || len(b.PreviousNonce) == 0 && len(b.ReplacementNonce) != 0 || len(b.PreviousNonce) != 0 && (len(b.PreviousNonce) != 32 || len(b.ReplacementNonce) != 32 || bytes.Equal(b.ReplacementNonce, b.PreviousNonce)) {
		return ErrConnectorLegBinding
	}
	return nil
}

func (b ConnectorLegBinding) Matches(proof ConnectorPairLegProof) bool {
	return b.Validate() == nil && bytes.Equal(b.Nonce, proof.Nonce)
}
