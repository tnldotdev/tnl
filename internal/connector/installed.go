package connector

import (
	"context"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
)

// Jobs lists or stops one installed connector. removal joins the supervisor's
// attempt before releasing the remembered local port.
func Jobs(ctx context.Context, options supervisor.ServiceOptions, name, action string) ([]supervisor.Job, error) {
	registry, err := supervisor.Open(ctx, supervisor.OpenOptions{Root: options.Root, User: true})
	if err != nil {
		return nil, err
	}
	defer registry.Close()
	jobs, err := registry.List(ctx)
	if err != nil {
		return nil, err
	}
	connectors := []supervisor.Job{}
	for _, job := range jobs {
		if job.Kind == "connector" && (name == "" || job.Name == name || job.ID == name) {
			connectors = append(connectors, job)
		}
	}
	if name == "" {
		return connectors, nil
	}
	if len(connectors) == 0 {
		return nil, supervisor.ErrJobNotFound
	}
	if len(connectors) != 1 {
		return nil, supervisor.ErrJobAmbiguous
	}
	job := connectors[0]
	if err := registry.Stop(ctx, job.ID); err != nil {
		return nil, err
	}
	if action == "remove" {
		wait, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := registry.WaitStopped(wait, job.ID); err != nil {
			return nil, err
		}
		if err := registry.Remove(ctx, job.ID); err != nil {
			return nil, err
		}
		database, err := clientstate.Open(ctx, job.StateDir)
		if err != nil {
			return nil, err
		}
		defer database.Close()
		profile, err := database.Server(ctx, job.Server)
		if err != nil {
			return nil, err
		}
		if err := profile.RemoveServicePort(ctx, job.IdentityID, job.ServiceID); err != nil {
			return nil, err
		}
		return connectors, nil
	}
	// status is read again after stop, matching the supervisor's current state.
	jobs, err = registry.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, current := range jobs {
		if current.ID == job.ID {
			return []supervisor.Job{current}, nil
		}
	}
	return []supervisor.Job{}, nil
}
