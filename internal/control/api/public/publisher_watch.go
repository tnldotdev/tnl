package public

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	failureproblem "github.com/tnldotdev/tnl/internal/failure/problem"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/serverhttp"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	maxPublisherWatchRuns   = 64
	maxPublisherWatchScopes = 2048
	publisherWatchInterval  = 250 * time.Millisecond
	publisherWatchWait      = 15 * time.Second
	publisherWatchQuery     = time.Second
	publisherWatchAuth      = 3 * time.Second
	watchLogRequestIDs      = 128
)

var errPublisherWatchStopped = errors.New("publisher watch stopped")
var watchUnbatchedLogBudget = operatorlog.NewBudget(4, 16)

func reportUnbatchedWatchFailure(ctx context.Context, operation failure.Operation, id string, err error) {
	if suppressed, allowed := watchUnbatchedLogBudget.Take(ctx, observability.WatchUnavailable); allowed {
		operatorlog.ReportFields(ctx, operation, failure.ServerAPIInternal, id, err, slog.Int64("suppressed", suppressed))
	}
}

type PublisherWatchStore interface {
	AuthorizeConnectorPeerWatch(context.Context, string, string, int64, string, time.Time) error
	CompareConnectorPeerWatchVersions(context.Context, []controlstate.ConnectorPeerWatchVersion) ([]controlstate.ConnectorPeerWatchVersion, error)
}

// PublisherWatch batches the control process's authorized waits. it owns no
// grants or database connections; waits release their own reservations.
type PublisherWatch struct {
	store PublisherWatchStore
	done  chan struct{}
	mu    sync.Mutex
	used  int
	waits map[*publisherWatchWaiter]struct{}
}

type publisherWatchWaiter struct {
	seen   []controlstate.ConnectorPeerWatchVersion
	result chan publisherWatchResult
}

type publisherWatchResult struct {
	changes   []controlstate.ConnectorPeerWatchVersion
	err       error
	requestID string
}

func NewPublisherWatch(store PublisherWatchStore) *PublisherWatch {
	return &PublisherWatch{store: store, done: make(chan struct{}), waits: make(map[*publisherWatchWaiter]struct{})}
}

// Run is owned and joined once by the control process.
func (watch *PublisherWatch) Run(ctx context.Context) error {
	ticker := time.NewTicker(publisherWatchInterval)
	defer ticker.Stop()
	defer close(watch.done)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			watch.compare(ctx)
		}
	}
}

func (watch *PublisherWatch) reserve(count int) bool {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if count > maxPublisherWatchScopes-watch.used {
		return false
	}
	watch.used += count
	return true
}

func (watch *PublisherWatch) release(count int) {
	watch.mu.Lock()
	defer watch.mu.Unlock()
	watch.used -= count
}

func (watch *PublisherWatch) compare(ctx context.Context) {
	watch.mu.Lock()
	waiters := make([]*publisherWatchWaiter, 0, len(watch.waits))
	for waiter := range watch.waits {
		waiters = append(waiters, waiter)
	}
	watch.mu.Unlock()
	if len(waiters) == 0 {
		return
	}
	seen := make(map[string]controlstate.ConnectorPeerWatchVersion)
	for _, waiter := range waiters {
		for _, scope := range waiter.seen {
			if previous, exists := seen[scope.RunID]; exists && previous != scope {
				// if two callers saw different states, request the current
				// revision once and compare it separately for each caller.
				seen[scope.RunID] = controlstate.ConnectorPeerWatchVersion{RunID: scope.RunID, Revision: -1}
			} else {
				seen[scope.RunID] = scope
			}
		}
	}
	batch := make([]controlstate.ConnectorPeerWatchVersion, 0, len(seen))
	for _, scope := range seen {
		batch = append(batch, scope)
	}
	current := make(map[string]controlstate.ConnectorPeerWatchVersion)
	started := time.Now()
	query, cancel := context.WithTimeout(ctx, publisherWatchQuery)
	defer cancel()
	var err error
	for len(batch) != 0 {
		count := min(len(batch), controlstate.MaxConnectorPeerWatchBatch)
		var rows []controlstate.ConnectorPeerWatchVersion
		rows, err = watch.store.CompareConnectorPeerWatchVersions(query, batch[:count])
		if err != nil {
			break
		}
		for _, row := range rows {
			current[row.RunID] = row
		}
		batch = batch[count:]
	}
	if err != nil {
		watch.comparisonFailed(ctx, waiters, len(seen), time.Since(started), err)
		return
	}
	watch.mu.Lock()
	defer watch.mu.Unlock()
	for _, waiter := range waiters {
		if _, live := watch.waits[waiter]; !live {
			continue
		}
		result := publisherWatchResult{}
		for _, scope := range waiter.seen {
			if latest, found := current[scope.RunID]; found && (latest != scope || latest.Revision == -1) {
				result.changes = append(result.changes, latest)
			}
		}
		if len(result.changes) != 0 {
			delete(watch.waits, waiter)
			waiter.result <- result
		}
	}
}

func (watch *PublisherWatch) comparisonFailed(ctx context.Context, waiters []*publisherWatchWaiter, scopes int, elapsed time.Duration, err error) {
	batchID := failureproblem.NewRequestID()
	// prepare ids outside the wait lock. the request goroutines may be
	// registering or canceling even while this batch is being reported.
	reserved := make([]string, len(waiters))
	for i := range reserved {
		reserved[i] = failureproblem.NewRequestID()
	}
	ids := make([]string, 0, len(waiters))
	watch.mu.Lock()
	for i, waiter := range waiters {
		if _, live := watch.waits[waiter]; !live {
			continue
		}
		delete(watch.waits, waiter)
		id := reserved[i]
		ids = append(ids, id)
		waiter.result <- publisherWatchResult{err: err, requestID: id}
	}
	watch.mu.Unlock()

	fields := []slog.Attr{slog.String("watch_batch_id", batchID), slog.Int("waiters", len(ids)), slog.Int("scopes", scopes),
		slog.Int64("elapsed_ms", elapsed.Milliseconds()), slog.String("cause", operatorlog.CauseClass(err))}
	var comparison *controlstate.WatchComparisonFailure
	if errors.As(err, &comparison) {
		fields = append(fields, slog.String("db_phase", comparison.Phase), slog.Int64("pool_acquire_ms", comparison.Acquire.Milliseconds()), slog.Int64("db_work_ms", comparison.Work.Milliseconds()))
	}
	// group reserved response ids instead of repeating the same failure once
	// per request. a waiter that disconnects may not send its reserved id.
	first := true
	for chunk := range slices.Chunk(ids, watchLogRequestIDs) {
		link := slog.String("request_ids", strings.Join(chunk, ","))
		if first {
			first = false
			operatorlog.ReportFields(ctx, "compare publisher watches", failure.ServerAPIInternal, "", err, append(fields, link)...)
		} else {
			operatorlog.Line(ctx, "publisher watch response ids", slog.String("watch_batch_id", batchID), link)
		}
	}
	if first {
		operatorlog.ReportFields(ctx, "compare publisher watches", failure.ServerAPIInternal, "", err, fields...)
	}
}

func (watch *PublisherWatch) wait(ctx context.Context, seen []controlstate.ConnectorPeerWatchVersion) publisherWatchResult {
	waiter := &publisherWatchWaiter{seen: seen, result: make(chan publisherWatchResult, 1)}
	watch.mu.Lock()
	watch.waits[waiter] = struct{}{}
	watch.mu.Unlock()
	defer func() {
		watch.mu.Lock()
		delete(watch.waits, waiter)
		watch.mu.Unlock()
	}()
	timeout := time.NewTimer(publisherWatchWait)
	defer timeout.Stop()
	select {
	case <-watch.done:
		return publisherWatchResult{err: errPublisherWatchStopped}
	case <-ctx.Done():
		return publisherWatchResult{err: ctx.Err()}
	case <-timeout.C:
		// the caller retains its original bookmark; a change racing the
		// timer will still be returned on the next wait.
		return publisherWatchResult{}
	case result := <-waiter.result:
		return result
	}
}

func watchAuthorityDenied(err error) bool {
	return err == controlstate.ErrServiceAccess || err == controlstate.ErrPublisherIdentity || err == controlstate.ErrGuestTrialSpent
}

func (watch *PublisherWatch) authorize(ctx context.Context, run controlv1.PublisherWatchRun) error {
	if err := watch.store.AuthorizeConnectorPeerWatch(ctx, run.ServiceId, run.ServiceRunId, run.RunNumber, run.RunToken, time.Now()); err != nil {
		return err
	}
	return ctx.Err()
}

func watchAuthorizationProblem(request, auth context.Context, w http.ResponseWriter, operation string, err error) {
	operationErr := err
	rollback, failed := err.(*controlstate.RollbackFailure)
	reportRollback := func(id string) {
		if failed {
			operatorlog.ReportContext(request, failure.Operation(operation+" rollback"), failure.ServerAPIInternal, id, rollback.RollbackErr)
		}
	}
	if request.Err() != nil {
		reportRollback("")
		return
	}
	if failed {
		operationErr = rollback.OperationErr
	}
	// an exhausted server-side observation budget grants nothing. let the
	// publisher retry without treating database contention as a terminal fault.
	if auth.Err() == context.DeadlineExceeded && failure.Only(operationErr, context.DeadlineExceeded) {
		id := writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "publisher watch authorization timed out")
		reportUnbatchedWatchFailure(request, failure.Operation(operation), id, operationErr)
		reportRollback(id)
		return
	}
	if !failed && errors.Is(err, controlstate.ErrPublisherWatchContended) {
		id := writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "publisher watch authorization temporarily unavailable")
		reportUnbatchedWatchFailure(request, failure.Operation(operation), id, err)
		return
	}
	serviceRunProblem(request, w, operation, err)
}

func (h *handler) WatchPublisherRuns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.acceptingNewWork(r.Context(), w) {
		return
	}
	watch := h.config.PublisherWatch
	if watch == nil {
		id := writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "publisher watch unavailable")
		reportUnbatchedWatchFailure(r.Context(), "publisher watch not configured", id, errPublisherWatchStopped)
		return
	}
	var body controlv1.PublisherWatchRequest
	if !serverhttp.DecodeJSONLimited(w, r, &body, 24<<10) {
		return
	}
	if len(body.Runs) == 0 || len(body.Runs) > maxPublisherWatchRuns {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publisher watch subscriptions")
		return
	}
	index := make(map[string]int, len(body.Runs))
	for i, run := range body.Runs {
		_, duplicate := index[run.ServiceRunId]
		if duplicate || !opaqueid.Valid(run.ServiceId, opaqueid.ServicePrefix) ||
			!opaqueid.Valid(run.ServiceRunId, opaqueid.ServiceRunPrefix) || run.RunNumber < 1 ||
			run.ConnectorRevision != nil && *run.ConnectorRevision < 0 ||
			run.PolicyBookmark != nil && !controlv1.ValidPublisherPolicyBookmark(*run.PolicyBookmark) {
			writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publisher watch subscriptions")
			return
		}
		if _, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(run.RunToken)); err != nil {
			writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publisher watch subscriptions")
			return
		}
		index[run.ServiceRunId] = i
	}
	if !watch.reserve(len(body.Runs)) {
		w.Header().Set("Retry-After", "1")
		writeProblem(w, http.StatusTooManyRequests, controlv1.RateLimited, "publisher watch at capacity")
		return
	}
	defer watch.release(len(body.Runs))

	seen := make([]controlstate.ConnectorPeerWatchVersion, 0, len(body.Runs))
	changes := make([]controlstate.ConnectorPeerWatchVersion, 0, len(body.Runs))
	auth, stop := context.WithTimeout(r.Context(), publisherWatchAuth)
	for _, run := range body.Runs {
		err := watch.authorize(auth, run)
		if watchAuthorityDenied(err) {
			changes = append(changes, controlstate.ConnectorPeerWatchVersion{RunID: run.ServiceRunId, Revision: -1})
			continue
		}
		if err != nil {
			stop()
			watchAuthorizationProblem(r.Context(), auth, w, "authorize publisher watch", err)
			return
		}
		revision := int64(-1)
		if run.ConnectorRevision != nil {
			revision = *run.ConnectorRevision
		}
		scope := controlstate.ConnectorPeerWatchVersion{RunID: run.ServiceRunId, Revision: revision}
		if run.PolicyBookmark != nil {
			scope.PolicyBookmark = *run.PolicyBookmark
		}
		seen = append(seen, scope)
	}
	stop()
	if len(changes) == 0 {
		result := watch.wait(r.Context(), seen)
		if result.err != nil {
			if r.Context().Err() == nil {
				const title = "publisher watch unavailable"
				if result.requestID != "" {
					failureproblem.WriteWithRequestID(w, result.requestID, http.StatusServiceUnavailable, string(controlv1.Unavailable), title, title, "")
				} else {
					id := writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, title)
					reportUnbatchedWatchFailure(r.Context(), "publisher watch stopped", id, result.err)
				}
			}
			return
		}
		auth, stop := context.WithTimeout(r.Context(), publisherWatchAuth)
		defer stop()
		for _, change := range result.changes {
			if change.Revision >= 0 {
				run := body.Runs[index[change.RunID]]
				err := watch.authorize(auth, run)
				if watchAuthorityDenied(err) {
					change.Revision = -1
					change.PolicyBookmark = ""
				} else if err != nil {
					watchAuthorizationProblem(r.Context(), auth, w, "recheck publisher watch", err)
					return
				}
			}
			changes = append(changes, change)
		}
	}
	response := controlv1.PublisherWatchResponse{Changes: make([]controlv1.PublisherWatchChange, 0, len(changes))}
	for _, change := range changes {
		response.Changes = append(response.Changes, controlv1.PublisherWatchChange{
			ConnectorRevision: change.Revision, ServiceRunId: change.RunID, PolicyBookmark: change.PolicyBookmark,
		})
	}
	writeJSON(w, http.StatusOK, response)
}
