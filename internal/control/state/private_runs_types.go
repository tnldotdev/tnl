package controlstate

import (
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// PrivateRunState is the existing result envelope; the stored lifecycle has its
// own type so prepared runs cannot be mistaken for active publisher runs.
type privateRunLifecycleState string

const (
	privateRunPrepared privateRunLifecycleState = "prepared"
	privateRunStarting privateRunLifecycleState = "starting"
	privateRunReady    privateRunLifecycleState = "ready"
	privateRunClosed   privateRunLifecycleState = "closed"
)

func (s privateRunLifecycleState) valid() bool {
	return s == privateRunPrepared || s.active() || s == privateRunClosed
}

func (s privateRunLifecycleState) active() bool {
	return s == privateRunStarting || s == privateRunReady
}

func activePrivateRun(run controlstatedb.ControlPrivateServiceRun, now time.Time) bool {
	return !run.ClosedAt.Valid && run.PublisherExpiresAt.Time.After(now) && privateRunLifecycleState(run.State).active()
}

func privateAssignmentState(s string) (PublisherConnectionState, error) {
	state := PublisherConnectionState(s)
	switch state {
	case PublisherConnectionAssigned, PublisherConnectionConnected, PublisherConnectionReady, PublisherConnectionClosed:
		return state, nil
	default:
		return "", ErrPrivateServiceAccess
	}
}

type privateRunBinding struct {
	serviceID, runID string
	number           int64
}

func checkedPrivateRunBinding(serviceID, runID string, number int64) (privateRunBinding, error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || !opaqueid.Valid(runID, opaqueid.PrivateRunPrefix) || number < 1 {
		return privateRunBinding{}, ErrPrivateServiceAccess
	}
	return privateRunBinding{serviceID: serviceID, runID: runID, number: number}, nil
}

func (b privateRunBinding) matches(run controlstatedb.ControlPrivateServiceRun) bool {
	return b.serviceID == run.PrivateServiceID && b.runID == run.ID && b.number == run.RunNumber
}

type privateAssignmentBinding struct {
	privateRunBinding
	connectionID string
	revision     int64
}

func checkedPrivateAssignmentBinding(serviceID, runID, connectionID string, number, revision int64) (privateAssignmentBinding, error) {
	run, err := checkedPrivateRunBinding(serviceID, runID, number)
	if err != nil || !opaqueid.Valid(connectionID, opaqueid.PublisherConnectionPrefix) || revision < 1 {
		return privateAssignmentBinding{}, ErrPrivateServiceAccess
	}
	return privateAssignmentBinding{privateRunBinding: run, connectionID: connectionID, revision: revision}, nil
}

func (b privateAssignmentBinding) matches(slot controlstatedb.ControlPrivateServiceConnectionSlot) bool {
	return b.serviceID == slot.PrivateServiceID && b.runID == slot.PrivateRunID && b.number == slot.RunNumber &&
		b.connectionID == slot.PublisherConnectionID && b.revision == slot.ConnectionAssignmentRevision
}

func nextPrivateRevision(value int64) (int64, error) {
	if value < 1 || value == math.MaxInt64 {
		return 0, ErrPrivateServiceConflict
	}
	return value + 1, nil
}
