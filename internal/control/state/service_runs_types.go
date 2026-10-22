package state

import (
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// ServiceRunState is the existing result envelope; the stored lifecycle has its
// own type so prepared runs cannot be mistaken for active publisher runs.
type serviceRunLifecycleState string

const (
	serviceRunPrepared serviceRunLifecycleState = "prepared"
	serviceRunStarting serviceRunLifecycleState = "starting"
	serviceRunReady    serviceRunLifecycleState = "ready"
	serviceRunClosed   serviceRunLifecycleState = "closed"
)

func (s serviceRunLifecycleState) valid() bool {
	return s == serviceRunPrepared || s.active() || s == serviceRunClosed
}

func (s serviceRunLifecycleState) active() bool {
	return s == serviceRunStarting || s == serviceRunReady
}

func activeServiceRun(run controlstatedb.ControlServiceRun, now time.Time) bool {
	return !run.ClosedAt.Valid && run.PublisherExpiresAt.Time.After(now) && serviceRunLifecycleState(run.State).active()
}

func privateAssignmentState(s string) (PublisherConnectionState, error) {
	state := PublisherConnectionState(s)
	switch state {
	case PublisherConnectionAssigned, PublisherConnectionConnected, PublisherConnectionReady, PublisherConnectionClosed:
		return state, nil
	default:
		return "", ErrServiceAccess
	}
}

type serviceRunBinding struct {
	serviceID, runID string
	number           int64
}

func checkedServiceRunBinding(serviceID, runID string, number int64) (serviceRunBinding, error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) || number < 1 {
		return serviceRunBinding{}, ErrServiceAccess
	}
	return serviceRunBinding{serviceID: serviceID, runID: runID, number: number}, nil
}

func (b serviceRunBinding) matches(run controlstatedb.ControlServiceRun) bool {
	return b.serviceID == run.ServiceID && b.runID == run.ID && b.number == run.RunNumber
}

type privateAssignmentBinding struct {
	serviceRunBinding
	connectionID string
	revision     int64
}

func checkedPrivateAssignmentBinding(serviceID, runID, connectionID string, number, revision int64) (privateAssignmentBinding, error) {
	run, err := checkedServiceRunBinding(serviceID, runID, number)
	if err != nil || !opaqueid.Valid(connectionID, opaqueid.PublisherConnectionPrefix) || revision < 1 {
		return privateAssignmentBinding{}, ErrServiceAccess
	}
	return privateAssignmentBinding{serviceRunBinding: run, connectionID: connectionID, revision: revision}, nil
}

func (b privateAssignmentBinding) matches(slot controlstatedb.ControlServiceConnectionSlot) bool {
	return b.serviceID == slot.ServiceID && b.runID == slot.ServiceRunID && b.number == slot.RunNumber &&
		b.connectionID == slot.PublisherConnectionID && b.revision == slot.ConnectionAssignmentRevision
}

func nextPrivateRevision(value int64) (int64, error) {
	if value < 1 || value == math.MaxInt64 {
		return 0, ErrServiceConflict
	}
	return value + 1, nil
}
