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
	_, err := b.Activation()
	return err
}

func (b ConnectorLegBinding) Matches(proof ConnectorPairLegProof) bool {
	return b.Validate() == nil && bytes.Equal(b.Nonce, proof.Nonce)
}

// ConnectorHelloNonce identifies one signed hello, not a replacement operation.
type ConnectorHelloNonce [32]byte

// ConnectorHandoffID identifies the selected carrier across fresh hello attempts.
type ConnectorHandoffID [32]byte

func ParseConnectorHelloNonce(wire []byte) (ConnectorHelloNonce, error) {
	if len(wire) != 32 {
		return ConnectorHelloNonce{}, ErrConnectorLegBinding
	}
	return ConnectorHelloNonce(wire), nil
}

// ConnectorHandoff keeps a validated predecessor and successor together.
type ConnectorHandoff struct {
	previous ConnectorHandoffID
	next     ConnectorHandoffID
}

func NewConnectorHandoff(previous, next ConnectorHandoffID) (ConnectorHandoff, error) {
	if previous == next {
		return ConnectorHandoff{}, ErrConnectorLegBinding
	}
	return ConnectorHandoff{previous: previous, next: next}, nil
}

func (h ConnectorHandoff) Previous() ConnectorHandoffID { return h.previous }
func (h ConnectorHandoff) Next() ConnectorHandoffID     { return h.next }
func (h ConnectorHandoff) Valid() bool                  { return h.previous != h.next }

// ConnectorActivation is the validated initial-or-replacement wire selection.
// its fixed-size identities are copied at the boundary, never aliased wire bytes.
type ConnectorActivation struct {
	hello   ConnectorHelloNonce
	handoff ConnectorHandoff
	replace bool
}

func InitialConnectorActivation(hello ConnectorHelloNonce) ConnectorActivation {
	return ConnectorActivation{hello: hello}
}

func (a ConnectorActivation) Replacing(handoff ConnectorHandoff) ConnectorActivation {
	a.handoff, a.replace = handoff, true
	return a
}

func (a ConnectorActivation) Hello() ConnectorHelloNonce            { return a.hello }
func (a ConnectorActivation) Replacement() (ConnectorHandoff, bool) { return a.handoff, a.replace }
func (a ConnectorActivation) SelectedHandoff() ConnectorHandoffID {
	if a.replace {
		return a.handoff.Next()
	}
	return ConnectorHandoffID(a.hello)
}

func (a ConnectorActivation) Matches(proof ConnectorPairLegProof) bool {
	hello, err := ParseConnectorHelloNonce(proof.Nonce)
	return err == nil && a.hello == hello && (!a.replace || a.handoff.Valid())
}

func (a ConnectorActivation) Binding() ConnectorLegBinding {
	b := ConnectorLegBinding{Nonce: append([]byte(nil), a.hello[:]...)}
	if a.replace {
		b.PreviousNonce = append([]byte(nil), a.handoff.previous[:]...)
		b.ReplacementNonce = append([]byte(nil), a.handoff.next[:]...)
	}
	return b
}

func (b ConnectorLegBinding) Activation() (ConnectorActivation, error) {
	hello, err := ParseConnectorHelloNonce(b.Nonce)
	if err != nil {
		return ConnectorActivation{}, err
	}
	a := InitialConnectorActivation(hello)
	if len(b.PreviousNonce) == 0 && len(b.ReplacementNonce) == 0 {
		return a, nil
	}
	if len(b.PreviousNonce) != 32 || len(b.ReplacementNonce) != 32 {
		return ConnectorActivation{}, ErrConnectorLegBinding
	}
	handoff, err := NewConnectorHandoff(ConnectorHandoffID(b.PreviousNonce), ConnectorHandoffID(b.ReplacementNonce))
	return a.Replacing(handoff), err
}
