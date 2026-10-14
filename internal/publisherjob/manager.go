package publisherjob

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"
)

// Run starts each saved URL independently and reconciles additions and stops.
// A failed target or server is retried without interrupting other jobs.
func Run(ctx context.Context, store *Store, publish func(context.Context, Job) error) error {
	return run(ctx, store, publish, 2*time.Second, 10*time.Second)
}

func run(ctx context.Context, store *Store, publish func(context.Context, Job) error, interval, retry time.Duration) error {
	type activeJob struct {
		cancel   context.CancelFunc
		sequence uint64
		key      []byte
		grant    string
	}
	active := make(map[string]activeJob)
	var sequence uint64
	next := make(map[string]time.Time)
	type completion struct {
		id       string
		sequence uint64
	}
	done := make(chan completion, 256)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer func() {
		for _, job := range active {
			job.cancel()
		}
	}()
	for {
		jobs, err := store.List()
		if err != nil {
			// a stop can remove a job after ReadDir but before List opens it.
			// keep the other jobs running and read a fresh snapshot next tick.
			if errors.Is(err, os.ErrNotExist) {
				info, statErr := os.Lstat(store.root)
				if statErr == nil && checkOwner(info, store.uid, true) == nil {
					select {
					case <-ctx.Done():
						return nil
					case <-ticker.C:
						continue
					}
				}
			}
			return err // never silently run only a subset of corrupt state.
		}
		present := make(map[string]bool, len(jobs))
		for _, job := range jobs {
			id := jobName(job.Server, job.ID())
			present[id] = true
			if running, ok := active[id]; ok && (!bytes.Equal(running.key, job.Private) || running.grant != job.Identity.GrantId) {
				running.cancel()
				delete(active, id)
				delete(next, id)
			}
			if _, running := active[id]; running || time.Now().Before(next[id]) {
				continue
			}
			jobCtx, cancel := context.WithCancel(ctx)
			sequence++
			current := sequence
			active[id] = activeJob{cancel: cancel, sequence: current, key: job.Private, grant: job.Identity.GrantId}
			go func() {
				_ = publish(jobCtx, job)
				select {
				case done <- completion{id, current}:
				case <-ctx.Done():
				}
			}()
		}
		for id, running := range active {
			if !present[id] {
				running.cancel()
				delete(active, id)
			}
		}
		for id := range next {
			if !present[id] {
				delete(next, id)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case completed := <-done:
			if running, ok := active[completed.id]; ok && running.sequence == completed.sequence {
				running.cancel()
				delete(active, completed.id)
				next[completed.id] = time.Now().Add(retry)
			}
		case <-ticker.C:
		}
	}
}

// ValidJob checks that state is still a saved URL enrollment, never a
// namespace allocation or a borrowed control session.
func ValidJob(job Job) error {
	if job.Identity.Kind != "saved_url" || job.Identity.PublicUrlId == nil || job.ID() == "" {
		return errors.New("a background publisher needs a saved public URL grant")
	}
	return nil
}
