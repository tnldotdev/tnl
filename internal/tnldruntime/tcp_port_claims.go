package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

const tcpPortClaimCleanupInterval = time.Minute

type tcpPortClaimStore interface {
	ReleaseQuarantinedTCPPortClaims(context.Context, time.Time) (int64, error)
	TCPPortPoolCapacities(context.Context) ([]controlstate.TCPPortPoolCapacity, error)
}

func runTCPPortClaimCleanup(ctx context.Context, store tcpPortClaimStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, tcpPortClaimCleanupInterval, func(ctx context.Context, now time.Time) (int, error) {
		count, err := store.ReleaseQuarantinedTCPPortClaims(ctx, now)
		if err == nil {
			var capacities []controlstate.TCPPortPoolCapacity
			capacities, err = store.TCPPortPoolCapacities(ctx)
			if err == nil {
				for _, pool := range capacities {
					metrics.SetTCPPortPoolCapacity(pool.IngressPoolID, pool.ConfiguredPorts, pool.ClaimedPorts, pool.QuarantinedPorts, pool.AvailablePorts)
				}
			}
		}
		return int(count), err // a batch releases at most 100 claims.
	}, func(released int, err error) {
		metrics.ObserveCleanup("tcp_port_claims", released, false, err)
		if err != nil && ctx.Err() == nil {
			logOperationalError("release quarantined TCP ports", failure.ServerWorkerFailed, err)
		}
	})
}
