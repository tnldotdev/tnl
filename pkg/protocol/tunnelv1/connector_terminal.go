package tunnelv1

import (
	"encoding/json"
	"io"
	"math"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const MaxConnectorTerminalBytes = 256

type ConnectorTerminalPurpose string

const (
	ConnectorTerminalCompletion ConnectorTerminalPurpose = "completion"
	ConnectorTerminalAbort      ConnectorTerminalPurpose = "abort"
)

func (p ConnectorTerminalPurpose) valid() bool {
	return p == ConnectorTerminalCompletion || p == ConnectorTerminalAbort
}

type ConnectorTerminalOutcome string

const (
	ConnectorTerminalAccepted ConnectorTerminalOutcome = "accepted"
	ConnectorTerminalRejected ConnectorTerminalOutcome = "rejected"
	ConnectorTerminalFailed   ConnectorTerminalOutcome = "failed"
)

func (o ConnectorTerminalOutcome) valid() bool {
	return o == ConnectorTerminalAccepted || o == ConnectorTerminalRejected || o == ConnectorTerminalFailed
}

const (
	ConnectorVisitorAborted              StreamKind = "connector_visitor_aborted"
	ConnectorVisitorTerminalResultKind   StreamKind = "connector_visitor_terminal_result"
	ConnectorVisitorTerminalObservedKind StreamKind = "connector_visitor_terminal_observed"
)

// the checked session supplies this immutable scope, never an inner message.
type ConnectorControlScope struct {
	ServiceID           string
	ServiceRunID        string
	RunNumber           uint64
	PublisherIdentityID string
	PairID              string
}

func (s ConnectorControlScope) Validate() error {
	if !opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(s.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		s.RunNumber == 0 || s.RunNumber > math.MaxInt64 ||
		!opaqueid.Valid(s.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(s.PairID, "cpp_") {
		return ErrConnectorPermissionUpdate
	}
	return nil
}

// the key keeps the accepted opening's generation even after network rebind.
// only the checked control scope together with this key identifies the admission.
type ConnectorVisitorTerminalKey struct {
	VisitorConnectionID string
	DeliveryGeneration  int64
}

func (k ConnectorVisitorTerminalKey) Validate() error {
	if !opaqueid.Valid(k.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || k.DeliveryGeneration < 1 {
		return ErrConnectorPermissionUpdate
	}
	return nil
}

// this normalized dispatch value is not an additional wire request.
type ConnectorVisitorTerminalRequest struct {
	Key            ConnectorVisitorTerminalKey
	Purpose        ConnectorTerminalPurpose
	TerminalNumber uint64
}

func (r ConnectorVisitorTerminalRequest) Validate() error {
	if r.Key.Validate() != nil || !r.Purpose.valid() || r.TerminalNumber == 0 {
		return ErrConnectorPermissionUpdate
	}
	return nil
}

type ConnectorVisitorAbort struct {
	Kind                StreamKind `json:"kind"`
	VisitorConnectionID string     `json:"visitor_connection_id"`
	DeliveryGeneration  int64      `json:"delivery_generation"`
	TerminalNumber      uint64     `json:"terminal_number"`
}

func (a ConnectorVisitorAbort) valid() bool {
	return a.Kind == ConnectorVisitorAborted && a.TerminalRequest().Validate() == nil
}

func (c ConnectorVisitorCompletion) TerminalRequest() ConnectorVisitorTerminalRequest {
	return ConnectorVisitorTerminalRequest{
		Key:            ConnectorVisitorTerminalKey{VisitorConnectionID: c.VisitorConnectionID, DeliveryGeneration: c.DeliveryGeneration},
		Purpose:        ConnectorTerminalCompletion,
		TerminalNumber: c.TerminalNumber,
	}
}

func (a ConnectorVisitorAbort) TerminalRequest() ConnectorVisitorTerminalRequest {
	return ConnectorVisitorTerminalRequest{
		Key:            ConnectorVisitorTerminalKey{VisitorConnectionID: a.VisitorConnectionID, DeliveryGeneration: a.DeliveryGeneration},
		Purpose:        ConnectorTerminalAbort,
		TerminalNumber: a.TerminalNumber,
	}
}

type ConnectorVisitorTerminalResult struct {
	Kind                StreamKind               `json:"kind"`
	VisitorConnectionID string                   `json:"visitor_connection_id"`
	DeliveryGeneration  int64                    `json:"delivery_generation"`
	TerminalNumber      uint64                   `json:"terminal_number"`
	Purpose             ConnectorTerminalPurpose `json:"purpose"`
	Outcome             ConnectorTerminalOutcome `json:"outcome"`
}

func (r ConnectorVisitorTerminalResult) valid() bool {
	return r.Kind == ConnectorVisitorTerminalResultKind && r.TerminalRequest().Validate() == nil && r.Outcome.valid()
}

func (r ConnectorVisitorTerminalResult) TerminalRequest() ConnectorVisitorTerminalRequest {
	return ConnectorVisitorTerminalRequest{
		Key:            ConnectorVisitorTerminalKey{VisitorConnectionID: r.VisitorConnectionID, DeliveryGeneration: r.DeliveryGeneration},
		Purpose:        r.Purpose,
		TerminalNumber: r.TerminalNumber,
	}
}

type ConnectorVisitorTerminalObserved struct {
	Kind                StreamKind               `json:"kind"`
	VisitorConnectionID string                   `json:"visitor_connection_id"`
	DeliveryGeneration  int64                    `json:"delivery_generation"`
	TerminalNumber      uint64                   `json:"terminal_number"`
	Purpose             ConnectorTerminalPurpose `json:"purpose"`
	Outcome             ConnectorTerminalOutcome `json:"outcome"`
}

func (o ConnectorVisitorTerminalObserved) valid() bool {
	return o.Kind == ConnectorVisitorTerminalObservedKind && o.TerminalRequest().Validate() == nil &&
		(o.Outcome == ConnectorTerminalAccepted || o.Outcome == ConnectorTerminalFailed)
}

func (o ConnectorVisitorTerminalObserved) TerminalRequest() ConnectorVisitorTerminalRequest {
	return ConnectorVisitorTerminalRequest{
		Key:            ConnectorVisitorTerminalKey{VisitorConnectionID: o.VisitorConnectionID, DeliveryGeneration: o.DeliveryGeneration},
		Purpose:        o.Purpose,
		TerminalNumber: o.TerminalNumber,
	}
}

func (ConnectorVisitorAbort) connectorControlMessage()            {}
func (ConnectorVisitorTerminalObserved) connectorControlMessage() {}

func WriteConnectorVisitorAbort(w io.Writer, a ConnectorVisitorAbort) error {
	if !a.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, a, MaxConnectorTerminalBytes)
}

func WriteConnectorVisitorTerminalResult(w io.Writer, r ConnectorVisitorTerminalResult) error {
	if !r.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, r, MaxConnectorTerminalBytes)
}

func WriteConnectorVisitorTerminalObserved(w io.Writer, o ConnectorVisitorTerminalObserved) error {
	if !o.valid() {
		return ErrConnectorPermissionUpdate
	}
	return writeJSONFrame(w, o, MaxConnectorTerminalBytes)
}

type ConnectorControlReply interface{ connectorControlReply() }

func (ConnectorPermissionResult) connectorControlReply()      {}
func (ConnectorVisitorTerminalResult) connectorControlReply() {}

// one reply decoder keeps permission results separate from terminal decisions.
func ReadConnectorControlReply(r io.Reader) (ConnectorControlReply, error) {
	payload, err := readFramePayload(r, MaxConnectorTerminalBytes)
	if err != nil {
		return nil, err
	}
	var header struct {
		Kind StreamKind `json:"kind"`
	}
	if json.Unmarshal(payload, &header) != nil {
		return nil, ErrConnectorPermissionUpdate
	}
	switch header.Kind {
	case ConnectorPermissionAccepted, ConnectorPermissionRejected, ConnectorPermissionStale:
		var result ConnectorPermissionResult
		if decodeConnectorControlPayload(payload, &result) != nil || !result.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return result, nil
	case ConnectorVisitorTerminalResultKind:
		var result ConnectorVisitorTerminalResult
		if decodeConnectorControlPayload(payload, &result) != nil || !result.valid() {
			return nil, ErrConnectorPermissionUpdate
		}
		return result, nil
	default:
		return nil, ErrConnectorPermissionUpdate
	}
}
