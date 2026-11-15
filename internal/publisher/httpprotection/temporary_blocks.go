package httpprotection

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Reporter func(context.Context, policy.Rejections) error

type ReportClient interface {
	ReportHTTPProtectionRejections(context.Context, controlv1.ReportHTTPProtectionRejectionsRequest, string) error
}

// RunReporter binds reports to current publisher authority. nil preparation
// facts fail closed when Prepare is called with temporary blocks enabled.
func RunReporter(client ReportClient, scope visitorscope.Scope, run string, number int64, token string) Reporter {
	if client == nil || !scope.Valid() || run == "" || number < 1 || token == "" {
		return nil
	}
	return func(ctx context.Context, evidence policy.Rejections) error {
		return client.ReportHTTPProtectionRejections(ctx, controlv1.ReportHTTPProtectionRejectionsRequest{
			Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID},
			RunId:    run, RunNumber: number, Evidence: evidence,
		}, token)
	}
}

// Prepare adds one joined reporting worker only for an explicit opt-in.
// callers supply the current run's reporting authority and refreshed block view.
func Prepare(ctx context.Context, settings policy.Settings, report Reporter, remote func(netip.Addr, time.Time) bool, key [32]byte) (*Inspector, error) {
	if settings.BlocksSources() && (ctx == nil || report == nil || remote == nil || key == [32]byte{}) {
		return nil, errors.New("temporary source blocks need current run reporting and policy")
	}
	p, err := New(settings)
	if err != nil {
		return nil, err
	}
	if settings.BlocksSources() {
		p.blocks = newTemporaryBlocks(ctx, report, remote, key)
	}
	return p, nil
}

type rejectionCount struct {
	started, blockedUntil time.Time
	count                 int
}

// temporaryBlocks owns bounded, opportunistic evidence for one publication.
// no request waits for reporting, and no counter is synchronized remotely.
type temporaryBlocks struct {
	mu        sync.Mutex
	key       [32]byte
	sources   map[string]rejectionCount
	nextSweep time.Time
	queue     chan policy.Rejections
	cancel    context.CancelFunc
	done      chan struct{}
	remote    func(netip.Addr, time.Time) bool
}

func newTemporaryBlocks(ctx context.Context, report Reporter, remote func(netip.Addr, time.Time) bool, key [32]byte) *temporaryBlocks {
	ctx, cancel := context.WithCancel(ctx)
	b := &temporaryBlocks{key: key, sources: make(map[string]rejectionCount), queue: make(chan policy.Rejections, 64), cancel: cancel, done: make(chan struct{}), remote: remote}
	go func() {
		defer close(b.done)
		for {
			select {
			case <-ctx.Done():
				return
			case evidence := <-b.queue:
				if ctx.Err() != nil {
					return
				}
				if evidence.Validate(time.Now()) != nil {
					continue
				}
				call, cancel := context.WithTimeout(ctx, 2*time.Second)
				_ = report(call, evidence)
				cancel()
			}
		}
	}()
	return b
}

func (b *temporaryBlocks) close() {
	if b != nil {
		b.cancel()
		<-b.done
	}
}

func (b *temporaryBlocks) blocked(source netip.Addr, now time.Time) bool {
	if b == nil {
		return false
	}
	digest, err := ippolicy.HashAddress(b.key, source)
	if err != nil {
		return false
	}
	b.mu.Lock()
	until := b.sources[digest].blockedUntil
	b.mu.Unlock()
	return now.Before(until) || b.remote != nil && b.remote(source, now)
}

func (b *temporaryBlocks) reject(source netip.Addr, result Result, now time.Time) {
	if b == nil || !source.IsValid() || source.Zone() != "" || result.Status != 403 || !slices.ContainsFunc(result.RuleIDs, policy.EligibleRule) {
		return
	}
	digest, err := ippolicy.HashAddress(b.key, source)
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	count, found := b.sources[digest]
	if now.Before(count.blockedUntil) {
		return
	}
	if !found && len(b.sources) >= 4096 {
		if now.Before(b.nextSweep) {
			return
		}
		b.nextSweep = now.Add(policy.BlockWindow)
		for ip, entry := range b.sources {
			if !now.Before(entry.blockedUntil) && !now.Before(entry.started.Add(policy.BlockWindow)) {
				delete(b.sources, ip)
			}
		}
		if len(b.sources) >= 4096 {
			return
		}
	}
	if count.started.IsZero() || now.Before(count.started) || !now.Before(count.started.Add(policy.BlockWindow)) {
		count = rejectionCount{started: now}
	}
	count.count++
	if count.count == policy.BlockThreshold {
		report := policy.Rejections{SourceDigest: digest, StartedAt: count.started, EndedAt: now, Count: count.count}
		for _, id := range result.RuleIDs {
			if policy.EligibleRule(id) {
				report.RuleIDs = append(report.RuleIDs, id)
				if len(report.RuleIDs) == 32 {
					break
				}
			}
		}
		count = rejectionCount{blockedUntil: now.Add(policy.BlockDuration)}
		select {
		case b.queue <- report:
		default:
		}
	}
	b.sources[digest] = count
}
