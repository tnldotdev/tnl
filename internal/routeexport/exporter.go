package routeexport

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

type Exporter struct {
	Store     *Store
	Collector *Collector
	Publisher *Publisher

	cancel context.CancelFunc
	done   chan struct{}
}

type Observer interface {
	ObserveRouteExportCheckpoint(string)
	ObserveRouteExportDelivery(string, string)
	SetRouteExportOutbox(string, int64)
	SetRouteExportOldestAge(time.Duration)
}

func New(db *sql.DB, rawURL, token string, observer Observer) (*Exporter, error) {
	store, err := NewStore(db)
	if err != nil {
		return nil, err
	}
	publisher, err := NewPublisher(store, rawURL, token, observer)
	if err != nil {
		return nil, err
	}
	return &Exporter{Store: store, Collector: NewCollector(store, observer), Publisher: publisher}, nil
}

func (e *Exporter) Start(ctx context.Context, report func(error)) error {
	if err := e.Collector.Recover(ctx); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.done = make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); e.Collector.Run(runCtx, report) }()
	go func() { defer workers.Done(); e.Publisher.Run(runCtx, report) }()
	go func() { workers.Wait(); close(e.done) }()
	return nil
}

func (e *Exporter) Close(ctx context.Context) error {
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
		delivered, err := e.Publisher.PublishOne(ctx)
		if err != nil {
			return errors.Join(result, err)
		}
		if !delivered {
			break
		}
	}
	return errors.Join(result, ctx.Err())
}
