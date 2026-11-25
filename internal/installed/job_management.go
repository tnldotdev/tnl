package installed

import (
	"context"
	"errors"
	"os"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
)

// StopJob requests a local stop without removing the installed definition,
// signing identity, or connector port assignment.
func (r *Registry) StopJob(ctx context.Context, id string) (Job, error) {
	if err := r.Stop(ctx, id); err != nil {
		return Job{}, err
	}
	return r.ResolveJob(ctx, id)
}

// RemoveJob stops an installed job, joins its worker, and removes local state.
func (r *Registry) RemoveJob(ctx context.Context, id string) (Job, error) {
	job, err := r.StopJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := r.WaitStopped(waitCtx, id); err != nil {
		return Job{}, err
	}
	if err := r.Remove(ctx, id); err != nil {
		return Job{}, err
	}
	job.Status = Status{State: JobStopped}
	return job, nil
}

// releaseConnectorPort runs under the registry lock after the worker has
// joined. A failed release leaves the stopped definition available for retry
// and an installed replacement cannot claim the binding during cleanup.
func releaseConnectorPort(ctx context.Context, job Job) (result error) {
	if _, err := os.Lstat(clientstate.DatabasePath(job.StateDir)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return failure.Wrap("inspect connector state", failure.ClientStateUnavailable, err)
	}
	database, err := clientstate.Open(ctx, job.StateDir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, database.Close()) }()
	profile, err := database.Server(ctx, job.Server)
	if err != nil {
		return err
	}
	return profile.RemoveServicePort(ctx, job.IdentityID, job.ServiceID)
}
