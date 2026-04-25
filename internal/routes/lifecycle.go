package routes

import (
	"context"
	"time"

	"github.com/0xcadams/tnl/internal/state/statedb"
)

type LifecycleTransition string

const (
	LifecycleGenerationStarted LifecycleTransition = "generation_started"
	LifecycleReady             LifecycleTransition = "ready"
	LifecycleDisconnected      LifecycleTransition = "disconnected"
	LifecycleDeleted           LifecycleTransition = "deleted"
)

type LifecycleChange struct {
	RouteID    string
	Generation uint64
	OccurredAt time.Time
	Transition LifecycleTransition
}

type LifecycleRecorder interface {
	RecordLifecycle(context.Context, *statedb.Queries, LifecycleChange) error
}
