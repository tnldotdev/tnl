// package livevisitor bounds the lifetime of active visitor permissions.
package livevisitor

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	RefreshInterval = 30 * time.Second
	MaxLifetime     = 2 * time.Minute
	checkTimeout    = 5 * time.Second
)

var (
	ErrDenied  = errors.New("visitor permission denied")
	ErrExpired = errors.New("visitor permission expired")
)

// Key binds a decision to an exact proof. SSHUser must be included for SSH;
// a database permission must never authorize an account-specific SSH session.
// source ports are deliberately excluded so concurrent connections can share a check.
type Key struct {
	PublicURLID, PublishRunID string
	PublishRunNumber          uint64
	SourceIP                  netip.Addr
	CertificateSHA256         [sha256.Size]byte
	SSHUser                   string
}

type Decision struct {
	Allowed    bool
	IdentityID string
	ValidUntil time.Time
}

// Check must consult current authority, bypass positive caches, and obey ctx.
// an explicit denial is Allowed=false with no error, or ErrDenied. other errors mean unknown;
// it rejects new sessions but cannot extend an existing session's deadline.
type Check func(context.Context) (Decision, error)

// Group retains only active proofs. its zero value is ready to use. callers
// must bound concurrent Acquire calls with their existing connection limits.
type Group struct {
	mu      sync.Mutex
	entries map[Key]*entry
	closed  bool
	workers sync.WaitGroup
}

type entry struct {
	ctx        context.Context
	cancel     context.CancelFunc
	finished   chan struct{}
	done       chan struct{}
	changed    chan struct{}
	refs       int
	refreshing bool
	decision   Decision
	refreshAt  time.Time
	err        error
	stopped    bool
}

// Lease belongs to one admitted connection. Done closes on denial, expiration,
// or group shutdown. Close releases its reference and joins the last checker.
type Lease struct {
	group *Group
	key   Key
	entry *entry
	once  sync.Once
}

func (l *Lease) Done() <-chan struct{} { return l.entry.done }

func (l *Lease) Close() {
	l.once.Do(func() {
		g, e := l.group, l.entry
		g.mu.Lock()
		e.refs--
		last := e.refs == 0
		if last {
			if g.entries[l.key] == e {
				delete(g.entries, l.key)
			}
			e.cancel()
		}
		g.mu.Unlock()
		if last {
			<-e.finished
		}
	})
}

// Acquire shares a fresh decision with other active connections for key. while
// a refresh is in flight, new sessions wait for its result instead of using the
// old decision. cancellation of one waiter never cancels another session's check.
func (g *Group) Acquire(ctx context.Context, key Key, check Check) (*Lease, Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, Decision{}, err
	}
	if key.PublicURLID == "" || key.PublishRunID == "" || key.PublishRunNumber == 0 || !key.SourceIP.IsValid() || key.SourceIP.Zone() != "" || key.SourceIP != key.SourceIP.Unmap() || check == nil {
		return nil, Decision{}, ErrDenied
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, Decision{}, context.Canceled
	}
	e := g.entries[key]
	if e == nil {
		life, cancel := context.WithCancel(context.Background())
		e = &entry{ctx: life, cancel: cancel, finished: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{}), refreshing: true}
		if g.entries == nil {
			g.entries = make(map[Key]*entry)
		}
		g.entries[key] = e
		g.workers.Go(func() { g.run(e, check) })
	}
	e.refs++
	lease := &Lease{group: g, key: key, entry: e}
	for {
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			lease.Close()
			return nil, Decision{}, err
		}
		if e.stopped || !e.refreshing && (e.err != nil || time.Now().Before(e.refreshAt)) {
			decision, err := e.decision, e.err
			if err == nil && !time.Now().Before(decision.ValidUntil) {
				err = ErrExpired
			}
			g.mu.Unlock()
			if err != nil {
				lease.Close()
				return nil, Decision{}, err
			}
			return lease, decision, nil
		}
		changed := e.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
		g.mu.Lock()
	}
}

func (g *Group) Close() {
	g.mu.Lock()
	g.closed = true
	for _, e := range g.entries {
		e.cancel()
	}
	g.mu.Unlock()
	g.workers.Wait()
}

func (g *Group) notify(e *entry) {
	close(e.changed)
	e.changed = make(chan struct{})
}

func (g *Group) stop(e *entry, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e.stopped, e.err = true, err
	close(e.done)
	g.notify(e)
}

type result struct {
	decision Decision
	err      error
}

func (g *Group) run(e *entry, check Check) {
	defer close(e.finished)
	refresh := time.NewTimer(0)
	defer refresh.Stop()
	var hard *time.Timer
	var hardC <-chan time.Time
	var response chan result
	var cancel context.CancelFunc
	var requested time.Time
	defer func() {
		if hard != nil {
			hard.Stop()
		}
		if cancel != nil {
			cancel()
			// Check owns no detached work after the last connection or run closes.
			<-response
		}
	}()
	for {
		select {
		case <-e.ctx.Done():
			g.stop(e, e.ctx.Err())
			return
		case <-hardC:
			g.stop(e, ErrExpired)
			return
		case <-refresh.C:
			g.mu.Lock()
			e.refreshing = true
			g.mu.Unlock()
			requested = time.Now()
			var ctx context.Context
			ctx, cancel = context.WithTimeout(e.ctx, checkTimeout)
			response = make(chan result, 1)
			reply := response
			go func() {
				decision, err := check(ctx)
				if err == nil {
					err = ctx.Err()
				}
				reply <- result{decision, err}
			}()
		case r := <-response:
			cancel()
			cancel, response = nil, nil
			now := time.Now()
			g.mu.Lock()
			previous := e.decision
			g.mu.Unlock()
			if !previous.ValidUntil.IsZero() && !now.Before(previous.ValidUntil) {
				g.stop(e, ErrExpired)
				return
			}
			if errors.Is(r.err, ErrDenied) {
				g.stop(e, r.err)
				return
			}
			if r.err == nil {
				if !r.decision.Allowed || previous.Allowed && previous.IdentityID != r.decision.IdentityID {
					g.stop(e, ErrDenied)
					return
				}
				if until := requested.Add(MaxLifetime); r.decision.ValidUntil.After(until) {
					r.decision.ValidUntil = until
				}
				if !now.Before(r.decision.ValidUntil) {
					g.stop(e, ErrExpired)
					return
				}
				if hard == nil {
					hard = time.NewTimer(time.Until(r.decision.ValidUntil))
					hardC = hard.C
				} else {
					hard.Reset(time.Until(r.decision.ValidUntil))
				}
			}
			g.mu.Lock()
			e.refreshing, e.err = false, r.err
			if r.err == nil {
				e.decision = r.decision
			}
			// a short run lease or grant can expire before the normal refresh.
			// start earlier so a healthy authority can renew it before the hard
			// boundary; the minimum interval bounds checks near grant expiry.
			e.refreshAt = requested.Add(RefreshInterval)
			if early := now.Add(max(time.Second, e.decision.ValidUntil.Sub(now)/2)); early.Before(e.refreshAt) {
				e.refreshAt = early
			}
			next := e.refreshAt
			g.notify(e)
			g.mu.Unlock()
			if r.err != nil && previous.ValidUntil.IsZero() {
				g.stop(e, r.err)
				return
			}
			refresh.Reset(max(0, time.Until(next)))
		}
	}
}
