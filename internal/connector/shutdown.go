package connector

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/tnldotdev/tnl/internal/connector/workload"
)

func (b *connectorConnectionBackend) Close(ctx context.Context) error {
	// all callers join the first synchronous cleanup and retain its result.
	// later cancellation cannot retroactively change completed cleanup.
	b.closeOnce.Do(func() { b.closeErr = b.close(ctx) })
	return b.closeErr
}

func (b *connectorConnectionBackend) close(ctx context.Context) error {
	var result error
	b.mu.Lock()
	b.closed = true
	if b.cleanupContext == nil {
		b.cleanupContext = ctx
	} else {
		ctx = b.cleanupContext
	}
	b.publishLocked()
	if b.cancel != nil {
		b.cancel()
	}
	var listeners []io.Closer
	for _, owner := range b.listeners {
		if owner.listener != nil {
			listeners = append(listeners, owner.listener)
		}
	}
	clients := []*workload.Client{b.workload}
	if b.replacement != nil {
		clients = append(clients, b.replacement.client)
	}
	b.mu.Unlock()
	// revocation and path cleanup share the caller's budget and start together.
	// failed releases cannot consume the time reserved for session revocation.
	var cleanup sync.WaitGroup
	var resultsMu sync.Mutex
	add := func(err error) { resultsMu.Lock(); result = errors.Join(result, err); resultsMu.Unlock() }
	seen := map[*workload.Client]bool{}
	var revokeMu sync.Mutex
	revoke := func(client *workload.Client) {
		revokeMu.Lock()
		if client == nil || seen[client] {
			revokeMu.Unlock()
			return
		}
		if _, err := client.Session(); err != nil {
			revokeMu.Unlock()
			return
		}
		seen[client] = true
		revokeMu.Unlock()
		add(client.Revoke(ctx))
	}
	for _, client := range clients {
		cleanup.Go(func() { revoke(client) })
	}
	cleanup.Go(func() {
		for _, listener := range listeners {
			add(listener.Close())
		}
	})
	cleanup.Go(func() {
		b.operations.Wait()
		// an exchange may have committed just as shutdown canceled its request.
		b.mu.Lock()
		pending := b.replacement
		b.mu.Unlock()
		if pending != nil {
			add(pending.recoverForCleanup(ctx))
			revoke(pending.client)
		}
		b.workers.Wait()
		b.mu.Lock()
		err := b.cleanupErr
		b.mu.Unlock()
		add(err)
		b.kubeMu.Lock()
		defer b.kubeMu.Unlock()
		if b.sessionKubeResult.File != "" {
			add(b.sessionKubePlan.CleanupSession(ctx, b.sessionKubeResult))
		}
		if b.human != nil {
			add(b.human.Close())
		}
	})
	// cancellation bounds the operations; it does not prove they have joined.
	cleanup.Wait()
	resultsMu.Lock()
	defer resultsMu.Unlock()
	return errors.Join(result, context.Cause(ctx))
}
