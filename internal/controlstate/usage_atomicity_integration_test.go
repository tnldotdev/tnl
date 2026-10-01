package controlstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationUsageFirstBucketAfterSessionWait(t *testing.T) {
	database, base, firstIngress, first := newIngressUsageFixture(t)
	secondIngress, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_second", IngressRunID: "run_second", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, base, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first.ObservedThrough, first.ConnectionAttempts = base.Add(20*time.Second), 1
	second := first
	second.ConnectionAttempts = 3
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	writer, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, writer)
	queries := controlstatedb.New(writer)
	lease, err := lockCurrentIngressLease(ctx, queries, firstIngress.IngressLeaseIdentity, first.ObservedThrough)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queries.EnsureIngressUsageRun(ctx, controlstatedb.EnsureIngressUsageRunParams{
		IngressID: firstIngress.IngressID, IngressRunID: firstIngress.IngressRunID,
		IngressLeaseRevision: int64(firstIngress.IngressLeaseRevision), StartedAt: lease.RegisteredAt,
		LeaseExpiresAt: lease.LeaseExpiresAt, ObservedThrough: lease.RegisteredAt,
	}); err != nil {
		t.Fatal(err)
	}
	// keep the first report and bucket uncommitted while the other ingress starts
	// its publish run lock statement. that statement's snapshot cannot see this bucket.
	latest, err := loadIngressUsageHistory(ctx, queries, firstIngress.IngressLeaseIdentity, []IngressUsageReport{first})
	if err != nil {
		t.Fatal(err)
	}
	if err := applyIngressUsageReport(ctx, queries, firstIngress.IngressLeaseIdentity, first, first.ObservedThrough, latest); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		done <- database.ReportIngressUsage(ctx, secondIngress.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{second}}, second.ObservedThrough)
	})
	waitForPostgresBlock(t, ctx, database, int32(writer.Conn().PgConn().PID()), done)
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	var attempts int64
	var data []byte
	if err := database.pool.QueryRow(ctx, `SELECT connection_attempts, histogram_data FROM control.public_url_usage_buckets WHERE public_url_id = $1`, first.PublicURLID).Scan(&attempts, &data); err != nil || attempts != 4 {
		t.Fatalf("concurrent first-bucket accounting: attempts=%d, %v", attempts, err)
	}
	var envelope ingressUsageHistogramEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Runs) != 2 || !bytes.Equal(envelope.Runs[firstIngress.IngressID+"\x00"+firstIngress.IngressRunID], first.HistogramData) ||
		!bytes.Equal(envelope.Runs[secondIngress.IngressID+"\x00"+secondIngress.IngressRunID], second.HistogramData) {
		t.Fatal("bucket read after waiting lost a concurrently committed histogram")
	}
}

func TestIntegrationUsagePageAdvancesRepeatedKeys(t *testing.T) {
	database, base, ingress, report := newIngressUsageFixture(t)
	versions := make([]IngressUsageReport, 5)
	for index := range versions {
		value := report
		value.ReportRevision, value.ConnectionAttempts, value.PolicyDenials = uint64(index+1), uint64(index+1), uint64(index+1)
		value.ObservedThrough = base.Add(time.Duration(index+1)*time.Second + 123*time.Nanosecond)
		if index%2 == 0 {
			value.BucketStart = value.BucketStart.In(time.FixedZone("other", 3600))
		}
		versions[index] = value
	}
	versions[3].Final = true
	for _, reports := range [][]IngressUsageReport{
		{versions[2], versions[0], versions[1], versions[1]},
		{versions[3], versions[0], versions[2]},
	} {
		if err := database.ReportIngressUsage(t.Context(), ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: reports}, base.Add(10*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.ReportIngressUsage(t.Context(), ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{versions[4]}}, base.Add(11*time.Second)); !errors.Is(err, ErrIngressUsageReportConflict) {
		t.Fatalf("advance after final report: %v", err)
	}
	var attempts, denials, reports int64
	if err := database.pool.QueryRow(t.Context(), `SELECT connection_attempts, policy_denials,
		(SELECT count(*) FROM control.ingress_usage_reports)
		FROM control.public_url_usage_buckets WHERE public_url_id = $1`, report.PublicURLID).Scan(&attempts, &denials, &reports); err != nil || attempts != 4 || denials != 4 || reports != 4 {
		t.Fatalf("repeated-key page accounting: attempts=%d denials=%d reports=%d: %v", attempts, denials, reports, err)
	}
}

func TestIntegrationUsageBatchRollsBackCounterExhaustion(t *testing.T) {
	database, base, ingress, first := newIngressUsageFixture(t)
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity}, base, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	before := readUsageRun(t, database, ingress)
	const originalDenials = int64(math.MaxInt64 - 1)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET policy_denials = $1 WHERE id = 'session_usage'`, originalDenials); err != nil {
		t.Fatal(err)
	}
	first.ObservedThrough, first.ConnectionAttempts, first.PolicyDenials = base.Add(20*time.Second), 1, 1
	second := first
	second.BucketStart, second.BucketEnd, second.ObservedThrough = first.BucketEnd, first.BucketEnd.Add(time.Minute), first.ObservedThrough.Add(time.Minute)
	observed := second.ObservedThrough
	err := database.ReportIngressUsage(t.Context(), ingress.IngressLeaseIdentity, IngressUsageBatch{
		Reports: []IngressUsageReport{second, first}, ObservedThrough: &observed,
	}, observed)
	if err == nil || !strings.Contains(err.Error(), "policy denial counter is exhausted") {
		t.Fatalf("expected exhausted session counter: %v", err)
	}
	var reports, buckets, denials int64
	if err := database.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control.ingress_usage_reports),
		(SELECT count(*) FROM control.public_url_usage_buckets),
		(SELECT policy_denials FROM control.publish_runs WHERE id = 'session_usage')`).Scan(&reports, &buckets, &denials); err != nil {
		t.Fatal(err)
	}
	after := readUsageRun(t, database, ingress)
	if reports != 0 || buckets != 0 || denials != originalDenials || !after.observed.Equal(before.observed) || after.complete {
		t.Fatalf("failed second report left partial page state: reports=%d buckets=%d denials=%d observed=%s", reports, buckets, denials, after.observed)
	}
}
