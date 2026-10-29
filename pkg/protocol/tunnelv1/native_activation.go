package tunnelv1

import (
	"bytes"
	"errors"
)

// NativeLegBinding selects one authenticated carrier candidate by the nonce in
// its signed hello. it neither refreshes authority nor admits an application.
type NativeLegBinding struct {
	Nonce         []byte `json:"nonce"`
	PreviousNonce []byte `json:"previous_nonce,omitempty"`
}

var ErrNativeLegBinding = errors.New("native carrier binding is invalid")

func (b NativeLegBinding) Validate() error {
	if len(b.Nonce) != 32 || (len(b.PreviousNonce) != 0 && (len(b.PreviousNonce) != 32 || bytes.Equal(b.Nonce, b.PreviousNonce))) {
		return ErrNativeLegBinding
	}
	return nil
}

func (b NativeLegBinding) Matches(proof NativePairLegProof) bool {
	return b.Validate() == nil && bytes.Equal(b.Nonce, proof.Nonce)
}
