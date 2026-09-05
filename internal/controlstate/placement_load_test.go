package controlstate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// Local load test: production session/claim transactions, one team,
// 1,000 pre-created routes, 64 workers, two eight-connection pools, four relays.
// HTTP, ACME, visitor traffic, and background heartbeats are deliberately absent.
func TestLoadPlacement(t *testing.T) {
	RunPlacementLoad(t, nil)
}

// RunPlacementLoad also lets the external test attach the real control API
// without creating a controlstate -> controlapi import cycle.
func RunPlacementLoad(t *testing.T, newHandler func(*Database, credentials.LoginToken, *observability.Metrics) http.Handler) {
	t.Helper()
	f := newControlLoadFixture(t)
	database, now, request := f.database, f.now, f.base
	routes, controls, leases := f.routes, f.controls, f.leases
	const parallel = 64
	var accessToken credentials.AccessToken
	var loginToken credentials.LoginToken
	if newHandler != nil {
		var err error
		loginToken, err = credentials.NewLoginToken()
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := credentials.ParseLoginToken(loginToken)
		if err != nil {
			t.Fatal(err)
		}
		session, err := database.createControlSession(t.Context(), controlstatedb.New(database.pool), request.ActingIdentityID,
			false, "login_token", verifier.SourceRevision(), time.Hour, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		accessToken = session.AccessToken
	}
	var handlers []http.Handler
	for index, control := range controls {
		if newHandler != nil {
			handlers = append(handlers, newHandler(control, loginToken, f.metrics[index]))
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
	started := time.Now()
	for worker := range parallel {
		workers.Go(func() {
			control := controls[(worker/16)%2]
			for ctx.Err() == nil {
				index := next.Add(1) - 1
				if index >= int64(routes) {
					return
				}
				candidate := f.request(int(index))
				if newHandler != nil {
					lookupCtx, stop := context.WithTimeout(ctx, 20*time.Second)
					err := placementLoadLookup(lookupCtx, handlers[(worker/16)%2], accessToken, candidate)
					stop()
					if err != nil {
						first.Do(func() { firstErr = err; cancel() })
						return
					}
				}
				callCtx, stop := context.WithTimeout(ctx, 20*time.Second)
				setup, err := control.CreateRouteSession(callCtx, candidate, now, time.Hour, time.Hour)
				stop()
				if err == nil {
					for _, assignment := range setup.PublisherConnections {
						digest, parseErr := credentials.ParsePublisherConnectionCredential(assignment.PublisherConnectionCredential)
						if parseErr != nil {
							err = parseErr
							break
						}
						callCtx, stop = context.WithTimeout(ctx, 20*time.Second)
						_, err = control.ClaimPublisherConnection(callCtx, PublisherConnectionClaimRequest{
							ConnectionAssignmentIdentity: assignment.ConnectionAssignmentIdentity,
							RelayLeaseIdentity:           leases[assignment.RelayServiceID][index%2].RelayLeaseIdentity,
							ClaimID:                      "load", CredentialDigest: [32]byte(digest),
						}, now)
						stop()
						if err != nil {
							break
						}
						claims.Add(1)
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
	t.Logf("completed=%d/%d claims=%d workers=%d pools=2x8 extra_query_delay=%s hostname_lookup=%t elapsed=%s", completed.Load(), routes, claims.Load(), parallel, f.delay, newHandler != nil, time.Since(started))
	if firstErr != nil || completed.Load() != int64(routes) {
		t.Fatalf("load failed: %v", firstErr)
	}
	assertAssignmentTotals(t, database.pool, int64(routes)*2)
}

func placementLoadLookup(ctx context.Context, handler http.Handler, token credentials.AccessToken, candidate RouteSessionRequest) error {
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/routes?team_id="+candidate.TeamID+"&canonical_hostname="+candidate.CertificateIdentifiers[0], nil)
	request.Header.Set("Authorization", "Bearer "+string(token))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("hostname lookup: %w", err)
	}
	if response.Code != http.StatusOK {
		return fmt.Errorf("hostname lookup: HTTP %d", response.Code)
	}
	var page controlv1.RoutePage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		return err
	}
	if len(page.Routes) != 1 || page.Routes[0].Id != candidate.RouteID || page.NextCursor != nil {
		return fmt.Errorf("hostname lookup returned an unexpected route page")
	}
	return nil
}

type queryDelayTracer struct {
	*connectionTracer
	delay time.Duration
}

func (r *queryDelayTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	r.connectionTracer.TraceQueryEnd(ctx, conn, data)
	// Optional client-side round-trip model, not a network emulator. Query
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
