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

type LifecycleRecorder interface {
	RecordLifecycle(context.Context, *statedb.Queries, LifecycleChange) error
}
