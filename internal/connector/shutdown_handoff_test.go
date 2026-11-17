package connector

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestForegroundConnectorOnlyHandsFinalStopBudgetToProcess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var recorded time.Time
		parent := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
			recorded = until
			return until
		})
		ctx, finish := connectorShutdownHandoff(parent)
		replaced := time.Now().Add(5 * time.Second)
		observability.ShutdownDeadline(ctx, replaced)
		finish(&connectorstream.MetadataReloadError{})
		if !recorded.IsZero() {
			t.Fatal("metadata replacement consumed the process exit budget", recorded)
		}
		time.Sleep(10 * time.Second)
		ctx, finish = connectorShutdownHandoff(parent)
		stopped := time.Now().Add(5 * time.Second)
		cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), observability.ShutdownDeadline(ctx, stopped))
		defer cancel()
		<-cleanup.Done()
		finish(context.Canceled)
		if !recorded.Equal(stopped) {
			t.Fatal("final foreground stop lost its already-spent cleanup budget", recorded, stopped)
		}
	})
}
