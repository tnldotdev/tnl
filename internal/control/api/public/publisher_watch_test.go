package public

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

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
