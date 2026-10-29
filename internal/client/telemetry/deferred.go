package telemetry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

// Deferred keeps the collector's state setup out of command startup. it retains
// at most 64 semantic observations while the collector opens. an off/on
// preference change fences them before they can reach the durable outbox.
type Deferred struct {
	initial clientstate.TelemetryPreference
	ctx     context.Context
	cancel  context.CancelFunc
	ready   atomic.Pointer[Collector]
	closed  atomic.Bool
	events  chan Observation
	wake    chan struct{}
	finish  chan deferredClose
	done    chan struct{}
	once    sync.Once
}

// preferenceReadTimeout bounds optional read-only setup on the command path.
// if it cannot establish the starting epoch, do not retain observations whose
// authority might have changed while the read was waiting.
const preferenceReadTimeout = 150 * time.Millisecond

// InstallationDisabled captures one job's invoking-state choice. the registry
// has its own preference and must not silently replace a saved source opt-out.
// unknown optional state disables that job without changing its siblings.
func InstallationDisabled(ctx context.Context, root string, disabled bool) bool {
	if disabled {
		return true
	}
	if root == "" {
		var err error
		root, err = clientstate.DefaultDir()
		if err != nil {
			return true
		}
	}
	read, cancel := context.WithTimeout(ctx, preferenceReadTimeout)
	defer cancel()
	preference, err := clientstate.TelemetryPreferenceAt(read, root)
	return err != nil || !preference.Enabled
}

type deferredClose struct {
	ctx context.Context
	ack chan struct{}
}

func NewDeferred(parent context.Context, config Config) (*Deferred, error) {
	return newDeferred(parent, config, New)
}

func newDeferred(parent context.Context, config Config, open func(context.Context, Config) (*Collector, error)) (*Deferred, error) {
	if config.Disabled {
		return nil, nil
	}
	if config.Root == "" || config.FlushInterval < 0 {
		return nil, errors.New("telemetry collection settings are invalid")
	}
	read, stop := context.WithTimeout(parent, preferenceReadTimeout)
	preference, err := clientstate.TelemetryPreferenceAt(read, config.Root)
	stop()
	if err != nil || !preference.Enabled {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	d := &Deferred{initial: preference, ctx: ctx, cancel: cancel,
		events: make(chan Observation, 64), wake: make(chan struct{}, 1), finish: make(chan deferredClose), done: make(chan struct{})}
	go d.run(config, open)
	return d, nil
}

func (d *Deferred) Report(observation Observation) {
	if d == nil || d.closed.Load() {
		return
	}
	if collector := d.ready.Load(); collector != nil {
		collector.Report(observation)
		return
	}
	select {
	case d.events <- observation:
	default:
	}
}

func (d *Deferred) Flush() {
	if d == nil || d.closed.Load() {
		return
	}
	if collector := d.ready.Load(); collector != nil {
		collector.Flush()
		return
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *Deferred) run(config Config, open func(context.Context, Config) (*Collector, error)) {
	defer close(d.done)
	collector, err := open(d.ctx, config)
	if err != nil || collector == nil {
		return
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), RequestTimeout)
		defer cancel()
		collector.Close(cleanup)
	}()
	d.drain(collector)
	d.ready.Store(collector)
	select {
	case <-d.wake:
		collector.Flush()
	default:
	}
	for {
		select {
		case <-d.ctx.Done():
			return
		case observation := <-d.events:
			d.reportInitial(collector, observation)
		case <-d.wake:
			collector.Flush()
		case request := <-d.finish:
			d.drain(collector)
			collector.Close(request.ctx)
			close(request.ack)
			return
		}
	}
}

func (d *Deferred) drain(collector *Collector) {
	for range cap(d.events) {
		select {
		case observation := <-d.events:
			d.reportInitial(collector, observation)
		default:
			return
		}
	}
}

func (d *Deferred) reportInitial(collector *Collector, observation Observation) {
	// a queued observation belongs to the initial epoch, even if the saved
	// preference was turned off and on while the collector was opening.
	// native70 cannot establish that history until its first amendment.
	if d.initial.Epoch < 0 {
		return
	}
	if preference := collector.preference.Load(); preference != nil && preference.Enabled && preference.Epoch == d.initial.Epoch {
		select {
		case collector.events <- queuedObservation{epoch: d.initial.Epoch, make: observation.wire}:
		default:
		}
	}
}

func (d *Deferred) Close(ctx context.Context) {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.closed.Store(true)
		ack := make(chan struct{})
		select {
		case d.finish <- deferredClose{ctx: ctx, ack: ack}:
			select {
			case <-ack:
			case <-ctx.Done():
			case <-d.done:
			}
		case <-ctx.Done():
		case <-d.done:
		}
		d.cancel()
		<-d.done
	})
}
