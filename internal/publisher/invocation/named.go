package invocation

import (
	"context"
	"errors"
	"os"
	"time"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	localpublisher "github.com/tnldotdev/tnl/internal/publisher/localapi"
	privateprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

// runNamedPublish acquires a configured service through the project owner. the
// parent CLI resolves project/config flags and calls this for named services.
// replacement owners are rediscovered and receive a fresh lease; an old owner
// capability or registration is never replayed against the replacement.
func PublishNamed(ctx context.Context, project projectconfig.Project, name, stateDir string, resolveOwner func(context.Context, projectconfig.Project, string) (privateprotocol.Endpoint, error), output *Presentation) (result error) {
	ctx, finishStartup := observability.ClientOperation(ctx, "client.publish.startup")
	defer func() { finishStartup(result) }()
	if _, found := project.Config.Services[name]; !found {
		return failure.Wrap("publish service", failure.ServiceNotConfigured, errors.New("service is not configured"))
	}
	if project.Config.Server == nil {
		server, state, err := resolveServer(ctx, stateDir, "")
		if err != nil {
			return err
		}
		if err := state.Close(); err != nil {
			return err
		}
		project.Config.Server = &server
	}
	_, digest, err := project.Snapshot()
	if err != nil {
		return err
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
		return resolveOwner(ctx, project, root)
	}, Request: privateprotocol.Lease{Service: name, Owner: ownerID, Pid: os.Getpid(), ConfigurationDigest: digest}}
	defer func() {
		cleanup, cancel := context.WithTimeout(observability.Independent(context.WithoutCancel(ctx)), 10*time.Second)
		defer cancel()
		cleanup, finish := observability.ClientOperation(cleanup, "client.publish.shutdown")
		finish(lease.Close(cleanup))
	}()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	lastRun := uint64(0)
	lastOwner, lastTunnel := "", ""
	lastPrivateTarget := ""
	var ownerRecoveryDeadline time.Time
	for {
		if ctx.Err() != nil {
			return output.stopped()
		}
		attempt, finishAttempt := ctx, func(error) {}
		if lastOwner != "" {
			if ownerRecoveryDeadline.IsZero() {
				attempt, finishAttempt = observability.ClientOperation(ctx, "client.publish.renew")
			} else {
				attempt, finishAttempt = observability.ClientOperation(ctx, "client.publish.recover")
			}
		}
		endpoint, registration, err := lease.Renew(attempt)
		finishAttempt(err)
		if err != nil {
			var response *privateprotocol.ResponseError
			if errors.As(err, &response) {
				if response.Code == "runtime.owner_conflict" {
					return failure.Wrap("acquire named service", failure.AppOwnerConflict, err)
				}
				if reason := failure.Reason(response.Code); reason != "" {
					if _, known := failure.DefinitionFor(reason); known {
						return failure.Wrap("acquire named service", reason, err)
					}
				}
			}
			if lastOwner == "" || errors.Is(err, privateprotocol.ErrUnauthorized) || errors.Is(err, privateprotocol.ErrForbidden) || errors.Is(err, clientruntime.ErrOwnerConflict) {
				return err
			}
			// a restarted local publisher may be unavailable until its new
			// scoped endpoint is ready.
			if ownerRecoveryDeadline.IsZero() {
				ownerRecoveryDeadline = time.Now().Add(45 * time.Second)
			}
			if time.Now().After(ownerRecoveryDeadline) {
				return err
			}
			select {
			case <-ctx.Done():
				return output.stopped()
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		ownerRecoveryDeadline = time.Time{}
		if lastOwner == "" {
			finishStartup(nil)
			ctx = observability.Independent(ctx)
		}
		if endpoint.OwnerId != lastOwner {
			lastOwner = endpoint.OwnerId
			lastRun = 0
			lastTunnel, lastPrivateTarget = "", ""
		}
		var snapshot clientruntime.Snapshot
		status, finishStatus := observability.ClientOperation(ctx, "client.publish.status")
		statusErr := privateprotocol.Call(status, endpoint, "GET", "/v1/status", nil, &snapshot)
		finishStatus(statusErr)
		if statusErr == nil {
			for _, service := range snapshot.Services {
				if service.Name != name || service.RegistrationID != registration.RegistrationID {
					continue
				}
				if service.PublicURL == "" && service.Target != "" && lastPrivateTarget != service.Target {
					if err := output.starting("", service.Target); err != nil {
						return err
					}
					lastPrivateTarget = service.Target
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
					reason := failure.TransportUnavailable
					if owned := failure.Reason(service.Failure); owned != "" {
						if _, known := failure.DefinitionFor(owned); known {
							reason = owned
						}
					}
					return failure.Wrap("publish service", reason, errors.New("service publication failed"))
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
