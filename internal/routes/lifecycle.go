package routes

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/state/statedb"
)

type LifecycleTransition string

const (
	LifecycleVersionStarted LifecycleTransition = "version_started"
	LifecycleReady          LifecycleTransition = "ready"
	LifecycleDisconnected   LifecycleTransition = "disconnected"
	LifecycleDeleted        LifecycleTransition = "deleted"
)

type LifecycleChange struct {
	RouteID    string
	Version    uint64
	OccurredAt time.Time
	Transition LifecycleTransition
}

type RouteRegistration struct {
	RegistrationID  string
	RouteID         string
	Hostname        string
	SigningKeyID    string
	AuthorizationID string
	CreatedAt       time.Time
	RetryID         string
}

type LifecycleRecorder interface {
	RecordRegistration(context.Context, *statedb.Queries, RouteRegistration) error
	RecordLifecycle(context.Context, *statedb.Queries, LifecycleChange) error
}
