package control

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// group waits only within this client: its origin and transport (including a
// portable host's fetch function) are part of its credential boundary.
type publisherWaits struct {
	mu     sync.Mutex
	groups []*publisherWaitGroup
}

type publisherWaitGroup struct {
	pending map[string]*publisherWait
	cancel  context.CancelFunc
	joined  chan struct{}
	done    chan struct{}
}

type publisherWait struct {
	scope  controlv1.PublisherWatchRun
	result chan publisherNotice
}

type publisherNotice struct {
	revision int64
	err      error
}

// WaitPublisherRun waits for one change. quiet HTTP responses renew only the
// wait. the caller supplies a new bookmark only after applying the fetched state.
func (c *Client) WaitPublisherRun(ctx context.Context, scope controlv1.PublisherWatchRun) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	w := &publisherWait{scope: scope, result: make(chan publisherNotice, 1)}
	owner := &c.publisherWaits
	owner.mu.Lock()
	var g *publisherWaitGroup
	for _, candidate := range owner.groups {
		if candidate.pending[scope.ServiceRunId] != nil {
			owner.mu.Unlock()
			return 0, failure.Wrap("watch service run", failure.ServerRequestInvalid, errors.New("duplicate service run subscription"))
		}
		if g == nil && len(candidate.pending) != 0 && len(candidate.pending) < 64 {
			g = candidate
		}
	}
	if g == nil {
		g = &publisherWaitGroup{pending: make(map[string]*publisherWait), done: make(chan struct{})}
		owner.groups = append(owner.groups, g)
		g.pending[scope.ServiceRunId] = w
		go c.runPublisherWaits(g)
	} else {
		g.pending[scope.ServiceRunId] = w
		if g.cancel != nil {
			g.cancel()
		}
	}
	owner.mu.Unlock()
	select {
	case result := <-w.result:
		return result.revision, result.err
	case <-ctx.Done():
		owner.mu.Lock()
		var joined chan struct{}
		if g.pending[scope.ServiceRunId] == w {
			delete(g.pending, scope.ServiceRunId)
			if g.cancel != nil {
				g.cancel()
				joined = g.joined
			}
			if len(g.pending) == 0 {
				joined = g.done
			}
		}
		owner.mu.Unlock()
		if joined != nil {
			<-joined
		}
		select {
		case result := <-w.result:
			return 0, errors.Join(context.Cause(ctx), result.err)
		default:
			return 0, context.Cause(ctx)
		}
	}
}

func (c *Client) runPublisherWaits(g *publisherWaitGroup) {
	owner := &c.publisherWaits
	owner.mu.Lock()
	defer owner.mu.Unlock()
	for len(g.pending) != 0 {
		scopes := make([]controlv1.PublisherWatchRun, 0, len(g.pending))
		for _, w := range g.pending {
			scopes = append(scopes, w.scope)
		}
		call, cancel := context.WithCancel(context.Background())
		g.cancel, g.joined = cancel, make(chan struct{})
		owner.mu.Unlock()
		changes, err := c.WatchPublisherRuns(call, scopes)
		owner.mu.Lock()
		replaced := call.Err() != nil
		cancel()
		close(g.joined)
		g.cancel, g.joined = nil, nil
		if replaced {
			continue
		}
		if err != nil {
			for id, w := range g.pending {
				delete(g.pending, id)
				w.result <- publisherNotice{err: err}
			}
			break
		}
		for _, change := range changes {
			w := g.pending[change.ServiceRunId]
			delete(g.pending, change.ServiceRunId)
			w.result <- publisherNotice{revision: change.ConnectorRevision}
		}
	}
	i := slices.Index(owner.groups, g)
	owner.groups = slices.Delete(owner.groups, i, i+1)
	close(g.done)
}
