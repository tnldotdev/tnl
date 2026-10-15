package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

// runNamedPublish acquires a configured service through the project owner. the
// parent CLI resolves project/config flags and calls this for named services.
// replacement owners are rediscovered and receive a fresh lease; an old owner
// capability or registration is never replayed against the replacement.
func runNamedPublish(ctx context.Context, project projectConfiguration, stateDir, name string, output *publishOutput) error {
	if _, found := project.Config.Services[name]; !found {
		return failure.Wrap("publish service", failure.ServiceNotConfigured, errors.New("service is not configured"))
	}
	root, err := clientStateRoot(stateDir)
	if err != nil {
		return err
	}
	ownerID, err := privateprotocol.Random(16)
	if err != nil {
		return err
	}
	lease := &localpublisher.LeaseClient{Resolve: func(ctx context.Context) (privateprotocol.Endpoint, error) {
		return ensureRuntimeOwner(ctx, project, root)
	}, Request: privateprotocol.Lease{Service: name, Owner: ownerID, Pid: os.Getpid()}}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = lease.Close(cleanup)
	}()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	lastRun := uint64(0)
	lastOwner, lastTunnel := "", ""
	for {
		if ctx.Err() != nil {
			return output.stopped()
		}
		endpoint, registration, err := lease.Renew(ctx)
		if err != nil {
			return err
		}
		if endpoint.OwnerId != lastOwner {
			lastOwner = endpoint.OwnerId
			lastRun = 0
		}
		var snapshot clientruntime.Snapshot
		if err := privateprotocol.Call(ctx, endpoint, "GET", "/v1/status", nil, &snapshot); err == nil {
			for _, service := range snapshot.Services {
				if service.Name != name || service.RegistrationID != registration.RegistrationID {
					continue
				}
				if service.TunnelID != "" && service.TunnelID != lastTunnel {
					if err := output.starting(service.TunnelID, service.Target); err != nil {
						return err
					}
					lastTunnel = service.TunnelID
				}
				if !service.Routable && service.PublishRunNumber != 0 {
					if err := output.provisioning(service.PublicURL, service.PublishRunNumber); err != nil {
						return err
					}
				}
				if service.Routable && service.PublishRunNumber != lastRun {
					if err := output.ready(service.PublicURL, service.PublishRunNumber); err != nil {
						return err
					}
					lastRun = service.PublishRunNumber
				}
				if !service.Routable && service.Failure != "" && service.ProvisioningStage == "" {
					return failure.Wrap("publish service", failure.TransportUnavailable, errors.New("service publication failed"))
				}
			}
		}
		select {
		case <-ctx.Done():
			return output.stopped()
		case <-ticker.C:
		}
	}
}
