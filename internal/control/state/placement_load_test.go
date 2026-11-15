package state

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// local load test: production service run and claim transactions, one team,
// 1,000 saved services, 64 workers, two eight-connection pools, four relays.
// HTTP, ACME, visitor traffic, and background heartbeats are deliberately absent.
func TestLoadPlacement(t *testing.T) {
	RunPlacementLoad(t, nil)
}

// RunPlacementLoad also lets the external test attach the real control API
// without creating a controlstate -> controlapi import cycle.
func RunPlacementLoad(t *testing.T, newHandler func(*Database, *observability.Metrics) http.Handler) {
	t.Helper()
	f := newControlLoadFixture(t)
	database, now := f.database, f.now
	routes, controls, leases := f.routes, f.controls, f.leases
	const parallel = 64
	var accessToken credentials.AccessToken
	if newHandler != nil {
		session, err := database.createControlSession(t.Context(), controlstatedb.New(database.pool), f.actorID,
			time.Hour, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		accessToken = session.AccessToken
	}
	var handlers []http.Handler
	for index, control := range controls {
		if newHandler != nil {
			handlers = append(handlers, newHandler(control, f.metrics[index]))
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	f.startMetrics(t)
	defer f.logStats(t)
	defer workers.stop()
	var next, completed, claims atomic.Int64
	var first sync.Once
	var firstErr error
	runs := make([]ServiceRunState, routes)
	started := time.Now()
	for worker := range parallel {
		workers.Go(func() {
			control := controls[(worker/16)%2]
			for ctx.Err() == nil {
				index := next.Add(1) - 1
				if index >= int64(routes) {
					return
				}
				i := int(index)
				service, publisher := f.services[i], f.publishers[i]
				request := f.request(i)
				if newHandler != nil {
					lookupCtx, stop := context.WithTimeout(ctx, 20*time.Second)
					err := placementLoadLookup(lookupCtx, handlers[(worker/16)%2], accessToken, service)
					stop()
					if err != nil {
						first.Do(func() { firstErr = err; cancel() })
						return
					}
				}
				callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
				prepared, err := control.PrepareServiceRun(callCtx, service.ID, publisher, fmt.Sprintf("placement-%d", i), now, request)
				stop()
				if err == nil {
					callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
					var run ServiceRunState
					run, err = control.StartServiceRun(callCtx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
					stop()
					if err == nil {
						if run.ServiceID != service.ID || run.RunID != prepared.RunID || run.RunNumber != prepared.RunNumber || len(run.Connections) != 2 {
							first.Do(func() { firstErr = fmt.Errorf("placement changed service/run tuple: %s", service.ID); cancel() })
							return
						}
						runs[i] = run
						for _, assignment := range run.Connections {
							callCtx2, stop2 := context.WithTimeout(ctx, 20*time.Second)
							var claimed ServicePublisherConnection
							claimed, err = control.ClaimServicePublisherConnection(callCtx2, assignment.PublisherConnectionID, service.ID,
								run.RunID, run.RunNumber, assignment.Revision, assignment.Credential,
								netip.MustParseAddr("127.0.0.1"), leases[assignment.RelayServiceID][i%2].RelayLeaseIdentity, now)
							stop2()
							if err == nil && claimed != (ServicePublisherConnection{ServiceID: service.ID, RunID: run.RunID, RunNumber: run.RunNumber,
								ConnectionID: assignment.PublisherConnectionID, Revision: assignment.Revision, RelayServiceID: assignment.RelayServiceID}) {
								err = fmt.Errorf("claim changed assignment identity for service %s", service.ID)
							}
							if err != nil {
								break
							}
							claims.Add(1)
						}
					}
				}
				if err != nil {
					first.Do(func() { firstErr = err; cancel() })
					return
				}
				completed.Add(1)
			}
		})
	}
	workers.Wait()
	t.Logf("completed=%d/%d claims=%d workers=%d pools=2x8 extra_query_delay=%s service_lookup=%t elapsed=%s", completed.Load(), routes, claims.Load(), parallel, f.delay, newHandler != nil, time.Since(started))
	if firstErr != nil || ctx.Err() != nil || completed.Load() != int64(routes) || claims.Load() != int64(routes)*2 {
		t.Fatalf("load failed: %v", firstErr)
	}
	for index, run := range runs {
		for _, slot := range run.Connections {
			lease := leases[slot.RelayServiceID][index%2]
			var matches bool
			err := database.pool.QueryRow(ctx, `SELECT slot.service_id=$2 AND slot.run_number=$3 AND slot.connection_assignment_revision=$4
				AND slot.relay_service_id=$5 AND slot.relay_id=$6 AND slot.relay_run_id=$7 AND slot.relay_lease_revision=$8
				AND slot.state='connected' AND slot.session_open AND run.closed_at IS NULL
				FROM control.service_connection_slots slot JOIN control.service_runs run ON run.id=slot.service_run_id
				WHERE slot.publisher_connection_id=$1 AND run.id=$9`, slot.PublisherConnectionID, f.services[index].ID,
				run.RunNumber, slot.Revision, slot.RelayServiceID, lease.RelayID, lease.RelayRunID, int64(lease.RelayLeaseRevision), run.RunID).Scan(&matches)
			if err != nil || !matches {
				t.Fatalf("durable placement tuple changed: service=%s slot=%d: %v", run.ServiceID, slot.ConnectionSlot, err)
			}
		}
	}
	assertAssignmentTotals(t, database.pool, int64(routes)*2)
}

func placementLoadLookup(ctx context.Context, handler http.Handler, token credentials.AccessToken, service ServiceRecord) error {
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/services/"+service.ID, nil)
	request.Header.Set("Authorization", "Bearer "+string(token))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("service lookup: %w", err)
	}
	if response.Code != http.StatusOK {
		return fmt.Errorf("service lookup: HTTP %d", response.Code)
	}
	var record controlv1.Service
	if err := json.Unmarshal(response.Body.Bytes(), &record); err != nil {
		return err
	}
	if record.Id != service.ID || record.TeamId != service.TeamID || record.Endpoint == nil || record.Endpoint.Hostname != service.Endpoint.Hostname {
		return fmt.Errorf("service lookup changed the service or its endpoint")
	}
	return nil
}

type queryDelayTracer struct {
	*connectionTracer
	delay time.Duration
}

func (r *queryDelayTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	r.connectionTracer.TraceQueryEnd(ctx, conn, data)
	// optional client-side round-trip model, not a network emulator. query
	// timings exclude their own delay; lock-held windows include earlier delays.
	if r.delay > 0 && data.Err == nil {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}
}
