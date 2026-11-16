package tnl

import (
	"context"
	"os"
	"strings"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/publisher/adhoc"
)

// the sdk owns its optional collector around the existing publication operation.
// a per-publication opt-out never writes the shared client's saved preference.
func runSDKPublication(ctx context.Context, state *clientstate.Database, options Options, publication adhoc.Options) error {
	value := os.Getenv("TNL_NO_TELEMETRY")
	if !options.NoTelemetry && value != "1" && !strings.EqualFold(value, "true") {
		collector, err := clienttelemetry.New(context.WithoutCancel(ctx), clienttelemetry.Config{
			Root: state.Root(), Protection: clientstate.ProtectionMode(options.StateProtection),
		})
		if err == nil {
			publication.Telemetry = collector
			defer func() {
				finish, cancel := context.WithTimeout(context.Background(), clienttelemetry.RequestTimeout)
				defer cancel()
				collector.Close(finish)
			}()
		}
	}
	return adhoc.Run(ctx, publication)
}
