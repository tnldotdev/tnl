package tnl

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/publisher/adhoc"
)

// the sdk owns its optional collector around the existing publication operation.
// a per-publication opt-out never writes the shared client's saved preference.
func runSDKPublication(ctx context.Context, state *clientstate.Database, options Options, publication adhoc.Options) (result error) {
	value := os.Getenv("TNL_NO_TELEMETRY")
	if !options.NoTelemetry && value != "1" && !strings.EqualFold(value, "true") {
		collector, err := clienttelemetry.New(context.WithoutCancel(ctx), clienttelemetry.Config{
			Root: state.Root(), Protection: clientstate.ProtectionMode(options.StateProtection),
		})
		if err == nil {
			publication.Telemetry = collector
			defer func() {
				result = errors.Join(result, closeSDKTelemetry(ctx, publication.ShutdownDeadline(), collector.Close))
			}()
		}
	}
	return adhoc.Run(ctx, publication)
}

// collector close cancels its in-flight request and joins its workers when the
// publication's original deadline expires, even if native drain spent it all.
func closeSDKTelemetry(ctx context.Context, until time.Time, close func(context.Context)) error {
	finish, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
	defer cancel()
	close(finish)
	return finish.Err()
}
