package tunnelv1

import (
	"bytes"
	"errors"
)

// ConnectorLegBinding selects one authenticated carrier candidate by the nonce in
// its signed hello. it neither refreshes authority nor admits an application.
type ConnectorLegBinding struct {
	Nonce []byte `json:"nonce"`
}

var ErrConnectorLegBinding = errors.New("connector carrier binding is invalid")

func (b ConnectorLegBinding) Validate() error {
	if len(b.Nonce) != 32 {
		return ErrConnectorLegBinding
	}
	return nil
}

func (b ConnectorLegBinding) Matches(proof ConnectorPairLegProof) bool {
	return b.Validate() == nil && bytes.Equal(b.Nonce, proof.Nonce)
}
