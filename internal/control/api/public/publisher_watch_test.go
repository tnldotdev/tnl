package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherWatchComparison503sShareOneLog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&output)
		defer log.SetOutput(previous)
		const secret = "do not log database text"
		store := &failedComparisonStore{watchTestStore{err: errors.Join(
			&controlstate.WatchComparisonFailure{Phase: "read_counters", Acquire: 2 * time.Millisecond, Work: 13 * time.Millisecond},
			&pgconn.PgError{Code: "57P01", Message: secret},
		)}}
		watch := NewPublisherWatch(store)
		h := testHandler(t, Config{PublisherWatch: watch}, nil, nil, nil)
		const body = `{"runs":[{"service_run_id":"` + publisherCORSRun + `","service_id":"` + publisherCORSService +
			`","run_number":"1","run_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","connector_revision":"0"}]}`
		var group sync.WaitGroup
		responses := make([]*httptest.ResponseRecorder, 3)
		for i := range responses {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/publisher/watch", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			responses[i] = httptest.NewRecorder()
			group.Go(func() { h.ServeHTTP(responses[i], r) })
		}
		synctest.Wait()
		watch.compare(t.Context())
		group.Wait()
		text := output.String()
		if strings.Count(text, "\n") != 1 || !strings.Contains(text, "watch_batch_id=req_") ||
			!strings.Contains(text, "sqlstate=57P01") || !strings.Contains(text, "waiters=3 scopes=1") || strings.Contains(text, secret) ||
			!strings.Contains(text, "db_phase=read_counters pool_acquire_ms=2 db_work_ms=13") ||
			strings.Contains(text, publisherCORSRun) || strings.Contains(text, "AAAAAAAAAAAAAAAA") {
			t.Fatalf("unsafe or ungrouped watch log: %q", text)
		}
		ids := make(map[string]bool)
		for _, w := range responses {
			var p controlv1.Problem
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != http.StatusServiceUnavailable ||
				p.Title != "publisher watch unavailable" || p.RequestId == "" || ids[p.RequestId] || !strings.Contains(text, p.RequestId) {
				t.Fatalf("response lost its correlation: %d %s", w.Code, w.Body.String())
			}
			ids[p.RequestId] = true
		}
	})
}

type failedComparisonStore struct{ watchTestStore }

func (*failedComparisonStore) AuthorizeConnectorPeerWatch(context.Context, string, string, int64, string, time.Time) error {
	return nil
}

type watchTestStore struct {
	batches   [][]controlstate.ConnectorPeerWatchVersion
	current   map[string]int64
	err       error
	denied    bool
	authCalls int
}

func (store *watchTestStore) AuthorizeConnectorPeerWatch(context.Context, string, string, int64, string, time.Time) error {
	store.authCalls++
	if store.denied {
		return controlstate.ErrServiceAccess
	}
	return nil
}

func (store *watchTestStore) CompareConnectorPeerWatchVersions(_ context.Context, scopes []controlstate.ConnectorPeerWatchVersion) ([]controlstate.ConnectorPeerWatchVersion, error) {
	store.batches = append(store.batches, slices.Clone(scopes))
	if store.err != nil {
		return nil, store.err
	}
	var changed []controlstate.ConnectorPeerWatchVersion
	for _, scope := range scopes {
		if revision := store.current[scope.RunID]; revision != scope.Revision {
			changed = append(changed, controlstate.ConnectorPeerWatchVersion{RunID: scope.RunID, Revision: revision})
		}
	}
	return changed, nil
}

func TestPublisherWatchBatchesWaitersWithoutAcknowledging(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &watchTestStore{current: map[string]int64{"a": 1, "b": 0}}
		watch := NewPublisherWatch(store)
		ctx, stop := context.WithCancel(t.Context())
		var group sync.WaitGroup
		defer func() {
			stop()
			group.Wait()
		}()
		group.Go(func() { _ = watch.Run(ctx) })
		begin := func(seen ...controlstate.ConnectorPeerWatchVersion) <-chan publisherWatchResult {
			inbox := make(chan publisherWatchResult, 1)
			group.Go(func() { inbox <- watch.wait(ctx, seen) })
			return inbox
		}
		applied := controlstate.ConnectorPeerWatchVersion{RunID: "a", Revision: 1}
		old := controlstate.ConnectorPeerWatchVersion{RunID: "a", Revision: 0}
		other := controlstate.ConnectorPeerWatchVersion{RunID: "b", Revision: 0}
		stale := begin(old)
		settled := begin(applied, other)
		synctest.Wait()
		time.Sleep(publisherWatchInterval)
		synctest.Wait()
		if len(store.batches) != 1 || len(store.batches[0]) != 2 {
			t.Fatalf("waiters did not share one comparison: %v", store.batches)
		}
		assertWatchHint(t, stale, applied)
		select {
		case result := <-settled:
			t.Fatalf("matching bookmarks received a hint: %v", result)
		default:
		}
		reconnected := begin(old)
		synctest.Wait()
		time.Sleep(publisherWatchInterval)
		synctest.Wait()
		assertWatchHint(t, reconnected, applied)
		stop()
		group.Wait()
		if result := <-settled; result.err == nil || len(result.changes) != 0 {
			t.Fatalf("shutdown emitted a hint: %v", result)
		}
		if len(watch.waits) != 0 {
			t.Fatal("shutdown retained an HTTP waiter")
		}
	})
}

func TestPublisherWatchCancellationAndScopeBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &watchTestStore{}
		watch := NewPublisherWatch(store)
		if !watch.reserve(maxPublisherWatchScopes) || watch.reserve(1) {
			t.Fatal("watch did not enforce its process-wide scope bound")
		}
		watch.release(maxPublisherWatchScopes)
		if !watch.reserve(1) {
			t.Fatal("watch did not release its scope budget")
		}
		watch.release(1)
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		done := make(chan publisherWatchResult, 1)
		go func() { done <- watch.wait(ctx, []controlstate.ConnectorPeerWatchVersion{{RunID: "a", Revision: 0}}) }()
		synctest.Wait()
		stop()
		if result := <-done; result.err != context.Canceled {
			t.Fatalf("canceled HTTP wait returned %v", result)
		}
		watch.compare(t.Context())
		if len(store.batches) != 0 {
			t.Fatal("canceled wait still used PostgreSQL")
		}
	})
}

func TestPublisherWatchQuietWaitDoesNotConfirmAnything(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		watch := NewPublisherWatch(&watchTestStore{})
		ctx, stop := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- watch.Run(ctx) }()
		defer func() {
			stop()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		begin := time.Now()
		result := watch.wait(ctx, []controlstate.ConnectorPeerWatchVersion{{RunID: "a", Revision: 0}})
		if result.err != nil || len(result.changes) != 0 || time.Since(begin) != publisherWatchWait {
			t.Fatalf("quiet watch = %v at %s", result, time.Since(begin))
		}
	})
}

func TestPublisherWatchBoundsBatchesAndDoesNotKeepFailedBookmarks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &watchTestStore{err: errors.New("unavailable")}
		watch := NewPublisherWatch(store)
		ctx, stop := context.WithCancel(t.Context())
		var group sync.WaitGroup
		defer func() {
			stop()
			group.Wait()
		}()
		results := make(chan publisherWatchResult, maxPublisherWatchScopes/maxPublisherWatchRuns)
		for start := 0; start < maxPublisherWatchScopes; start += maxPublisherWatchRuns {
			scopes := make([]controlstate.ConnectorPeerWatchVersion, maxPublisherWatchRuns)
			for i := range scopes {
				scopes[i] = controlstate.ConnectorPeerWatchVersion{RunID: strconv.Itoa(start + i), Revision: -1}
			}
			group.Go(func() { results <- watch.wait(ctx, scopes) })
		}
		synctest.Wait()
		watch.compare(ctx)
		for range cap(results) {
			result := <-results
			if result.err != store.err || len(result.changes) != 0 {
				t.Fatalf("failed batch produced a hint: %v", result)
			}
		}
		if len(store.batches) != 1 || len(store.batches[0]) != controlstate.MaxConnectorPeerWatchBatch || len(watch.waits) != 0 {
			t.Fatal("failed comparison continued or retained subscriptions")
		}

		store.err, store.batches = nil, nil
		scope := controlstate.ConnectorPeerWatchVersion{RunID: "0", Revision: -1}
		group.Go(func() { results <- watch.wait(ctx, []controlstate.ConnectorPeerWatchVersion{scope}) })
		synctest.Wait()
		watch.compare(ctx)
		synctest.Wait()
		assertWatchHint(t, results, controlstate.ConnectorPeerWatchVersion{RunID: "0", Revision: 0})
	})
}

func TestPublisherWatchRejectsInvalidSubscriptionsBeforeStateReads(t *testing.T) {
	const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const run = `{"service_run_id":"` + publisherCORSRun + `","service_id":"` + publisherCORSService +
		`","run_number":"1","run_token":"` + token + `"}`
	store := &watchTestStore{denied: true}
	watch := NewPublisherWatch(store)
	handler := testHandler(t, Config{PublisherWatch: watch}, nil, nil, nil)
	for name, body := range map[string]string{
		"empty":               `{"runs":[]}`,
		"duplicate run":       `{"runs":[` + run + `,` + run + `]}`,
		"too many":            `{"runs":[` + strings.Repeat(run+`,`, maxPublisherWatchRuns) + run + `]}`,
		"invalid token":       strings.ReplaceAll(`{"runs":[`+run+`]}`, token, "invalid"),
		"invalid bookmark":    `{"runs":[` + strings.TrimSuffix(run, "}") + `,"connector_revision":"-2"}]}`,
		"unexpected property": `{"runs":[` + strings.TrimSuffix(run, "}") + `,"scope":"all"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/publisher/watch", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://browser.example")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || w.Header().Get("Cache-Control") != "no-store" ||
				w.Header().Get("Access-Control-Allow-Origin") != "*" || strings.Contains(w.Body.String(), token) {
				t.Fatalf("invalid subscription response = %d, %v", w.Code, w.Header())
			}
			if store.authCalls != 0 || len(watch.waits) != 0 {
				t.Fatal("invalid subscription reached watch state")
			}
		})
	}
}

func TestPublisherWatchRechecksAuthorityBeforeReturningChangedScope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &watchTestStore{current: map[string]int64{publisherCORSRun: 0}}
		watch := NewPublisherWatch(store)
		h := testHandler(t, Config{PublisherWatch: watch}, nil, nil, nil)
		ctx, stop := context.WithCancel(t.Context())
		var group sync.WaitGroup
		defer func() {
			stop()
			group.Wait()
		}()
		const body = `{"runs":[{"service_run_id":"` + publisherCORSRun + `","service_id":"` + publisherCORSService +
			`","run_number":"1","run_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","connector_revision":"0"}]}`
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/publisher/watch", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		finished := make(chan struct{})
		group.Go(func() {
			defer close(finished)
			h.ServeHTTP(w, r)
		})
		synctest.Wait()
		if store.authCalls != 1 {
			t.Fatal("watch was not authenticated before waiting")
		}
		// a commit changes the watched version after authorization has succeeded,
		// and the publisher loses authority before observing that change.
		store.denied = true
		store.current[publisherCORSRun] = 1
		watch.compare(ctx)
		<-finished
		var result controlv1.PublisherWatchResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusOK || store.authCalls != 2 ||
			!slices.Equal(result.Changes, []controlv1.PublisherWatchChange{{ServiceRunId: publisherCORSRun, ConnectorRevision: -1}}) {
			t.Fatalf("revoked scope received a positive hint: %d, %v, %v", w.Code, result.Changes, err)
		}
	})
}

type stalledWatchAuthorization struct {
	watchTestStore
	stallAt int
	fail    func(error) error
}

func (s *stalledWatchAuthorization) AuthorizeConnectorPeerWatch(ctx context.Context, _ string, _ string, _ int64, _ string, _ time.Time) error {
	s.authCalls++
	if s.authCalls == s.stallAt {
		<-ctx.Done()
		return s.fail(ctx.Err())
	}
	return nil
}

func TestPublisherWatchAuthorizationTimeoutReturnsUnavailable(t *testing.T) {
	storageErr := errors.New("private database detail")
	for _, tc := range []struct {
		name           string
		fail           func(error) error
		status         int
		loggedRollback bool
	}{
		{"deadline", func(e error) error { return e }, 503, false},
		{"authorization finished after deadline", func(error) error { return nil }, 503, false},
		{"database contention", func(error) error { return controlstate.ErrPublisherWatchContended }, 503, false},
		{"deadline and rollback failure", func(e error) error {
			return &controlstate.RollbackFailure{OperationErr: fmt.Errorf("query: %w", e), RollbackErr: storageErr}
		}, 503, true},
		{"unrelated operation failure", func(e error) error { return errors.Join(e, storageErr) }, 500, false},
		{"only rollback timed out", func(e error) error {
			return &controlstate.RollbackFailure{OperationErr: storageErr, RollbackErr: e}
		}, 500, false},
	} {
		for at, phase := range []string{"initial", "recheck"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var logs bytes.Buffer
					previous := log.Writer()
					log.SetOutput(&logs)
					defer log.SetOutput(previous)
					store := &stalledWatchAuthorization{stallAt: at + 1, fail: tc.fail}
					store.current = map[string]int64{publisherCORSRun: 1}
					watch := NewPublisherWatch(store)
					ctx, stop := context.WithCancel(t.Context())
					done := make(chan error, 1)
					go func() { done <- watch.Run(ctx) }()
					defer func() { stop(); <-done }()
					body := `{"runs":[{"service_run_id":"` + publisherCORSRun + `","service_id":"` + publisherCORSService +
						`","run_number":"1","run_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","connector_revision":"0"}]}`
					r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/publisher/watch", strings.NewReader(body))
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					testHandler(t, Config{PublisherWatch: watch}, nil, nil, nil).ServeHTTP(w, r)
					if w.Code != tc.status || watch.used != 0 || store.authCalls != store.stallAt ||
						strings.Contains(w.Body.String(), "changes") || strings.Contains(w.Body.String(), publisherCORSRun) {
						t.Fatalf("watch timeout returned %d, reserved scopes %d", w.Code, watch.used)
					}
					var problem controlv1.Problem
					if json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.RequestId == "" ||
						tc.loggedRollback != strings.Contains(logs.String(), "watch rollback") ||
						tc.loggedRollback && !strings.Contains(logs.String(), problem.RequestId) ||
						strings.Contains(w.Body.String()+logs.String(), storageErr.Error()) {
						t.Fatalf("watch lost safe rollback diagnostics: %s, %s", w.Body.String(), logs.String())
					}
				})
			})
		}
	}
}

func TestPublisherWatchReportsRollbackAfterRequestEnds(t *testing.T) {
	request, cancel := context.WithCancel(t.Context())
	cancel()
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	w := httptest.NewRecorder()
	watchAuthorizationProblem(request, request, w, "authorize publisher watch", &controlstate.RollbackFailure{
		OperationErr: request.Err(), RollbackErr: errors.New("private cleanup failure"),
	})
	if w.Body.Len() != 0 || !strings.Contains(logs.String(), "authorize publisher watch rollback") || strings.Contains(logs.String(), "private cleanup failure") {
		t.Fatal("ended watch wrote a response or lost safe rollback diagnostics")
	}
}

func assertWatchHint(t *testing.T, ready <-chan publisherWatchResult, want ...controlstate.ConnectorPeerWatchVersion) {
	t.Helper()
	select {
	case result := <-ready:
		if result.err != nil || !slices.Equal(result.changes, want) {
			t.Fatalf("watch hint = %v, want %v", result, want)
		}
	default:
		t.Fatal("watch did not return changes")
	}
}
