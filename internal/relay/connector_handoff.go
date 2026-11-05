package relay

import (
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type handoffResult uint8

const (
	handoffRejected handoffResult = iota
	handoffRetried
	handoffAdvanced
	handoffExhausted
)

// handoffState owns the logical commit, separately from carrier installation.
// callers hold the bridge state lock and validate authority before recording.
// only the last operation is retained: the revision fences all older operations,
// and an exact retry still needs a fresh hello without advancing the revision.
type handoffState struct {
	selected   tunnelv1.ConnectorHandoffID
	operation  tunnelv1.ConnectorHandoff
	hello      tunnelv1.ConnectorHelloNonce
	selectedAt time.Time
}

func initialHandoff(selection tunnelv1.ConnectorActivation, at time.Time) handoffState {
	id := selection.SelectedHandoff()
	return handoffState{selected: id, hello: selection.Hello(), selectedAt: at}
}

func (s *handoffState) record(selection tunnelv1.ConnectorActivation, at time.Time) handoffResult {
	handoff, replacement := selection.Replacement()
	if !replacement || !handoff.Valid() || !at.After(s.selectedAt) || selection.Hello() == s.hello {
		return handoffRejected
	}
	result := handoffRejected
	if s.operation == handoff {
		result = handoffRetried
	} else {
		next, err := s.operation.Revision().Next()
		if err != nil {
			return handoffExhausted
		}
		if handoff.Revision() == next && s.selected == handoff.Previous() {
			result = handoffAdvanced
		}
	}
	if result != handoffRejected {
		// this commit survives a lost activation reply or canceled installation.
		s.operation, s.selected, s.hello, s.selectedAt = handoff, handoff.Next(), selection.Hello(), at
	}
	return result
}
