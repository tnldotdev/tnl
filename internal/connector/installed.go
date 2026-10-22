package connector

import (
	"context"
	"time"

	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

// Jobs lists or stops one installed connector. removal joins the supervisor's
// attempt before releasing the remembered local port.
func Jobs(ctx context.Context, options publisherjob.ServiceOptions, name, action string) ([]publisherjob.Job, error) {
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: true})
	if err != nil {
		return nil, err
	}
	defer registry.Close()
	jobs, err := registry.List(ctx)
	if err != nil {
		return nil, err
	}
	connectors := []publisherjob.Job{}
	for _, job := range jobs {
		if job.Kind == "connector" && (name == "" || job.Name == name || job.ID == name) {
			connectors = append(connectors, job)
		}
	}
	if name == "" {
		return connectors, nil
	}
	if len(connectors) == 0 {
		return nil, publisherjob.ErrJobNotFound
	}
	if len(connectors) != 1 {
		return nil, publisherjob.ErrJobAmbiguous
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
		if err := profile.RemovePrivateServicePort(ctx, job.IdentityID, job.PrivateServiceID); err != nil {
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
			return []publisherjob.Job{current}, nil
		}
	}
	return []publisherjob.Job{}, nil
}
