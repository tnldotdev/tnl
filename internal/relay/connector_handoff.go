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
)

// handoffState owns the logical commit, separately from carrier installation.
// callers hold the bridge state lock and validate authority before recording.
type handoffState struct {
	selected   tunnelv1.ConnectorHandoffID
	previous   tunnelv1.ConnectorHandoffID
	selectedAt time.Time
	used       map[tunnelv1.ConnectorHandoffID]bool
}

func initialHandoff(selection tunnelv1.ConnectorActivation, at time.Time) handoffState {
	id := selection.SelectedHandoff()
	return handoffState{selected: id, selectedAt: at, used: map[tunnelv1.ConnectorHandoffID]bool{id: true}}
}

func (s *handoffState) record(selection tunnelv1.ConnectorActivation, at time.Time) handoffResult {
	handoff, replacement := selection.Replacement()
	if !replacement || !handoff.Valid() || !at.After(s.selectedAt) {
		return handoffRejected
	}
	result := handoffRejected
	if s.selected == handoff.Next() && s.previous == handoff.Previous() {
		result = handoffRetried
	} else if s.selected == handoff.Previous() && !s.used[handoff.Next()] && len(s.used) < 64 {
		result = handoffAdvanced
	}
	if result != handoffRejected {
		// this commit survives a lost activation reply or canceled installation.
		s.previous, s.selected, s.selectedAt = handoff.Previous(), handoff.Next(), at
		s.used[handoff.Next()] = true
	}
	return result
}
