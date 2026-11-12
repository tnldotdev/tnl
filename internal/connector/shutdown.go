package connector

import (
	"context"
	"errors"
	"sync"

	"github.com/tnldotdev/tnl/internal/connector/workload"
)

func (b *connectorConnectionBackend) Close(ctx context.Context) error {
	var result error
	b.mu.Lock()
	b.closed = true
	b.cleanupContext = ctx
	b.publishLocked()
	if b.cancel != nil {
		b.cancel()
	}
	for _, owner := range b.listeners {
		if owner.listener != nil {
			result = errors.Join(result, owner.listener.Close())
		}
	}
	clients := []*workload.Client{b.workload}
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
		b.operations.Wait()
		if b.scope.Environment != nil && b.workload != nil && b.environmentPreparationUncertain && b.assertion != "" {
			selection := b.scope.Environment
			_, err := b.workload.Prepare(ctx, selection.Environment, selection.PermissionID, b.assertion, selection.Services)
			add(err)
			if err == nil {
				revoke(b.workload)
			}
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
	done := make(chan struct{})
	go func() { cleanup.Wait(); close(done) }()
	<-done
	if ctx.Err() != nil {
		resultsMu.Lock()
		result = errors.Join(result, ctx.Err())
		resultsMu.Unlock()
	}
	resultsMu.Lock()
	defer resultsMu.Unlock()
	return result
}
