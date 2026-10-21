package controlstate

import (
	"context"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
)

// WorkloadHistoryRetention follows service audit's authored history policy.
// expiry, rather than lease loss or revocation, bounds credential/replay lifetime.
const WorkloadHistoryRetention = serviceaudit.Retention

const workloadVisitorRetention = 24 * time.Hour

// CleanupWorkloads prunes at most limit rows from each of nine relations, in
// dependency order. each statement commits separately: later phases see removed
// children, and a timeout does not discard progress. blocked parents are filtered
// before selection so retained/live references cannot starve unrelated history.
func (d *Database) CleanupWorkloads(ctx context.Context, now time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 10000 {
		return 0, ErrWorkloadDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q := controlstatedb.New(d.pool)
	before := timestamptz(now.Add(-WorkloadHistoryRetention))
	visitorsBefore := timestamptz(now.Add(-workloadVisitorRetention))
	batch := int32(limit)
	phases := []struct {
		name string
		run  func() (int64, error)
	}{
		{"streams", func() (int64, error) {
			return q.CleanupWorkloadStreams(ctx, controlstatedb.CleanupWorkloadStreamsParams{BeforeTime: visitorsBefore, BatchSize: batch})
		}},
		{"direct visitors", func() (int64, error) {
			return q.CleanupWorkloadDirectVisitors(ctx, controlstatedb.CleanupWorkloadDirectVisitorsParams{BeforeTime: visitorsBefore, BatchSize: batch})
		}},
		{"connectors", func() (int64, error) {
			return q.CleanupWorkloadConnectors(ctx, controlstatedb.CleanupWorkloadConnectorsParams{BeforeTime: before, BatchSize: batch})
		}},
		{"certificates", func() (int64, error) {
			return q.CleanupWorkloadCertificates(ctx, controlstatedb.CleanupWorkloadCertificatesParams{BeforeTime: before, BatchSize: batch})
		}},
		{"ingress requests", func() (int64, error) {
			return q.CleanupWorkloadIngressRequests(ctx, controlstatedb.CleanupWorkloadIngressRequestsParams{BeforeTime: before, BatchSize: batch})
		}},
		{"assertions", func() (int64, error) {
			return q.CleanupWorkloadAssertions(ctx, controlstatedb.CleanupWorkloadAssertionsParams{BeforeTime: before, BatchSize: batch})
		}},
		{"audit", func() (int64, error) {
			return q.CleanupWorkloadAudit(ctx, controlstatedb.CleanupWorkloadAuditParams{BeforeTime: before, BatchSize: batch})
		}},
		{"service rights", func() (int64, error) {
			return q.CleanupWorkloadServiceRights(ctx, controlstatedb.CleanupWorkloadServiceRightsParams{BeforeTime: before, BatchSize: batch})
		}},
		{"sessions", func() (int64, error) {
			return q.CleanupWorkloadSessions(ctx, controlstatedb.CleanupWorkloadSessionsParams{BeforeTime: before, BatchSize: batch})
		}},
	}
	var removed int64
	for _, phase := range phases {
		n, err := phase.run()
		removed += n
		if err != nil {
			return removed, fmt.Errorf("clean up workload %s: %w", phase.name, err)
		}
	}
	return removed, nil
}
