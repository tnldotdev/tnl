package routeusage

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

type Reporter struct {
	Store     *Store
	Collector *Collector
	Sender    *Sender

	cancel context.CancelFunc
	done   chan struct{}
}

type Observer interface {
	ObserveRouteUsageCheckpoint(string)
	ObserveRouteUsageDelivery(string, string)
	SetRouteUsageOutbox(string, int64)
	SetRouteUsageOldestAge(time.Duration)
}

func New(db *sql.DB, rawURL, token string, observer Observer) (*Reporter, error) {
	store, err := NewStore(db)
	if err != nil {
		return nil, err
	}
	sender, err := NewSender(store, rawURL, token, observer)
	if err != nil {
		return nil, err
	}
	return &Reporter{Store: store, Collector: NewCollector(store, observer), Sender: sender}, nil
}

func (e *Reporter) Start(ctx context.Context, report func(error)) error {
	if err := e.Collector.Recover(ctx); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.done = make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); e.Collector.Run(runCtx, report) }()
	go func() { defer workers.Done(); e.Sender.Run(runCtx, report) }()
	go func() { workers.Wait(); close(e.done) }()
	return nil
}

func (e *Reporter) Close(ctx context.Context) error {
	if e.cancel == nil {
		return nil
	}
	e.cancel()
	select {
	case <-e.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	var result error
	if err := e.Collector.Checkpoint(ctx, time.Now().UTC(), true); err != nil {
		result = errors.Join(result, err)
	}
	for ctx.Err() == nil {
		delivered, err := e.Sender.SendOne(ctx)
		if err != nil {
			return errors.Join(result, err)
		}
		if !delivered {
			break
		}
	}
	return errors.Join(result, ctx.Err())
}
