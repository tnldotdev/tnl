package tunnelv1

import (
	"bytes"
	"errors"
	"math"
)

// ConnectorLegBinding selects one authenticated carrier candidate by the nonce in
// its signed hello. it neither refreshes authority nor admits an application.
type ConnectorLegBinding struct {
	Nonce            []byte `json:"nonce"`
	InitialHandoffID []byte `json:"initial_handoff_id,omitempty"`
	PreviousNonce    []byte `json:"previous_nonce,omitempty"`
	// replacement_nonce identifies one handoff across fresh hello attempts.
	ReplacementNonce []byte                   `json:"replacement_nonce,omitempty"`
	HandoffRevision  ConnectorHandoffRevision `json:"handoff_revision,omitempty"`
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

// ConnectorHandoffRevision orders operations for one retained relay path.
// zero selects the initial hello; replacements start at one and never wrap.
type ConnectorHandoffRevision uint64

var ErrConnectorHandoffRevisionExhausted = errors.New("connector handoff revision exhausted")

func (r ConnectorHandoffRevision) Next() (ConnectorHandoffRevision, error) {
	if r == math.MaxUint64 {
		return 0, ErrConnectorHandoffRevisionExhausted
	}
	return r + 1, nil
}

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
	revision ConnectorHandoffRevision
}

func NewConnectorHandoff(previous, next ConnectorHandoffID, revision ConnectorHandoffRevision) (ConnectorHandoff, error) {
	if previous == next || revision == 0 {
		return ConnectorHandoff{}, ErrConnectorLegBinding
	}
	return ConnectorHandoff{previous: previous, next: next, revision: revision}, nil
}

func (h ConnectorHandoff) Previous() ConnectorHandoffID       { return h.previous }
func (h ConnectorHandoff) Next() ConnectorHandoffID           { return h.next }
func (h ConnectorHandoff) Revision() ConnectorHandoffRevision { return h.revision }
func (h ConnectorHandoff) Valid() bool                        { return h.previous != h.next && h.revision != 0 }

// ConnectorActivation is the validated initial-or-replacement wire selection.
// its fixed-size identities are copied at the boundary, never aliased wire bytes.
type ConnectorActivation struct {
	hello      ConnectorHelloNonce
	handoff    ConnectorHandoff
	replace    bool
	initial    ConnectorHandoffID
	initialSet bool
}

func InitialConnectorActivation(hello ConnectorHelloNonce) ConnectorActivation {
	return ConnectorActivation{hello: hello}
}

// InitialConnectorBindingActivation selects a stable initial operation across
// fresh hellos. the relay binds it to the authenticated delivery generation and
// envelope key; it is not an authority credential or a new numbered handoff.
func InitialConnectorBindingActivation(hello ConnectorHelloNonce, operation ConnectorHandoffID) (ConnectorActivation, error) {
	if operation == (ConnectorHandoffID{}) {
		return ConnectorActivation{}, ErrConnectorLegBinding
	}
	return ConnectorActivation{hello: hello, initial: operation, initialSet: true}, nil
}

func (a ConnectorActivation) Replacing(handoff ConnectorHandoff) ConnectorActivation {
	a.handoff, a.replace = handoff, true
	a.initial, a.initialSet = ConnectorHandoffID{}, false
	return a
}

func (a ConnectorActivation) Hello() ConnectorHelloNonce            { return a.hello }
func (a ConnectorActivation) Replacement() (ConnectorHandoff, bool) { return a.handoff, a.replace }
func (a ConnectorActivation) InitialOperation() (ConnectorHandoffID, bool) {
	return a.initial, a.initialSet
}
func (a ConnectorActivation) SelectedHandoff() ConnectorHandoffID {
	if a.replace {
		return a.handoff.Next()
	}
	if a.initialSet {
		return a.initial
	}
	return ConnectorHandoffID(a.hello)
}

func (a ConnectorActivation) Matches(proof ConnectorPairLegProof) bool {
	hello, err := ParseConnectorHelloNonce(proof.Nonce)
	return err == nil && a.hello == hello && (!a.replace || a.handoff.Valid()) && (!a.initialSet || a.initial != (ConnectorHandoffID{}) && !a.replace)
}

func (a ConnectorActivation) Binding() ConnectorLegBinding {
	b := ConnectorLegBinding{Nonce: append([]byte(nil), a.hello[:]...)}
	if a.initialSet {
		b.InitialHandoffID = append([]byte(nil), a.initial[:]...)
	}
	if a.replace {
		b.PreviousNonce = append([]byte(nil), a.handoff.previous[:]...)
		b.ReplacementNonce = append([]byte(nil), a.handoff.next[:]...)
		b.HandoffRevision = a.handoff.revision
	}
	return b
}

func (b ConnectorLegBinding) Activation() (ConnectorActivation, error) {
	hello, err := ParseConnectorHelloNonce(b.Nonce)
	if err != nil {
		return ConnectorActivation{}, err
	}
	a := InitialConnectorActivation(hello)
	if len(b.InitialHandoffID) != 0 {
		if len(b.InitialHandoffID) != 32 || len(b.PreviousNonce) != 0 || len(b.ReplacementNonce) != 0 || b.HandoffRevision != 0 {
			return ConnectorActivation{}, ErrConnectorLegBinding
		}
		return InitialConnectorBindingActivation(hello, ConnectorHandoffID(b.InitialHandoffID))
	}
	if len(b.PreviousNonce) == 0 && len(b.ReplacementNonce) == 0 && b.HandoffRevision == 0 {
		return a, nil
	}
	if len(b.PreviousNonce) != 32 || len(b.ReplacementNonce) != 32 {
		return ConnectorActivation{}, ErrConnectorLegBinding
	}
	handoff, err := NewConnectorHandoff(ConnectorHandoffID(b.PreviousNonce), ConnectorHandoffID(b.ReplacementNonce), b.HandoffRevision)
	return a.Replacing(handoff), err
}
