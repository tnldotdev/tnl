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

type ServiceRunReference struct {
	ServiceID, RunID string
	RunNumber        int64
}

func checkedServiceRunBinding(serviceID, runID string, number int64) (ServiceRunReference, error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) || number < 1 {
		return ServiceRunReference{}, ErrServiceAccess
	}
	return ServiceRunReference{ServiceID: serviceID, RunID: runID, RunNumber: number}, nil
}

func (b ServiceRunReference) matches(run controlstatedb.ControlServiceRun) bool {
	return b.ServiceID == run.ServiceID && b.RunID == run.ID && b.RunNumber == run.RunNumber
}

type privateAssignmentBinding struct {
	ServiceRunReference
	connectionID string
	revision     int64
}

func checkedPrivateAssignmentBinding(serviceID, runID, connectionID string, number, revision int64) (privateAssignmentBinding, error) {
	run, err := checkedServiceRunBinding(serviceID, runID, number)
	if err != nil || !opaqueid.Valid(connectionID, opaqueid.PublisherConnectionPrefix) || revision < 1 {
		return privateAssignmentBinding{}, ErrServiceAccess
	}
	return privateAssignmentBinding{ServiceRunReference: run, connectionID: connectionID, revision: revision}, nil
}

func (b privateAssignmentBinding) matches(slot controlstatedb.ControlServiceConnectionSlot) bool {
	return b.ServiceID == slot.ServiceID && b.RunID == slot.ServiceRunID && b.RunNumber == slot.RunNumber &&
		b.connectionID == slot.PublisherConnectionID && b.revision == slot.ConnectionAssignmentRevision
}

func nextPrivateRevision(value int64) (int64, error) {
	if value < 1 || value == math.MaxInt64 {
		return 0, ErrServiceConflict
	}
	return value + 1, nil
}
