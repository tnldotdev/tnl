package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type resolvedNamedInvocation struct {
	project projectConfiguration
	service string
}

type resolvedPublicInvocation struct{ resolvedNamedInvocation }
type resolvedPrivateInvocation struct {
	resolvedNamedInvocation
	protocol controlv1.PrivateServiceProtocol
}

// namedInvocation carries the selected project, never an implicit config reload.
// the owner cannot change one lease's policy independently of its other workers.
func namedInvocation(flags publishCommand) (resolvedNamedInvocation, error) {
	if flags.namedOverrides {
		return resolvedNamedInvocation{}, publisherCLIError("named project publishing uses configured policy; set public URL, TLS, limits, and inspection options in the selected configuration")
	}
	if flags.AccessToken != "" || os.Getenv("TNL_ACCESS_TOKEN") != "" {
		return resolvedNamedInvocation{}, publisherCLIError("named project publishing uses its saved session; omit the access token or publish an explicit target")
	}
	project := flags.project
	if project.Config.Team != nil && flags.selectedTeam == "" {
		return resolvedNamedInvocation{}, publisherCLIError("select --team explicitly when publishing this project on another server")
	}
	if flags.ServerURL != "" {
		server, err := clientstate.CanonicalServer(flags.ServerURL)
		if err != nil {
			return resolvedNamedInvocation{}, err
		}
		project.Config.Server = &server
	}
	project.Config.Team = nil
	if flags.selectedTeam != "" {
		team := flags.selectedTeam
		project.Config.Team = &team
	}
	return resolvedNamedInvocation{project: project, service: flags.Service}, nil
}

func resolveNamedPublic(flags publishCommand) (resolvedPublicInvocation, error) {
	invocation, err := namedInvocation(flags)
	if err == nil && !config.IsPublicService(invocation.project.Config.Services[invocation.service]) {
		err = publisherCLIError("configured service is private")
	}
	return resolvedPublicInvocation{invocation}, err
}

func resolveNamedPrivate(flags publishCommand) (resolvedPrivateInvocation, error) {
	invocation, err := namedInvocation(flags)
	protocol := controlv1.PrivateServiceProtocol(flags.Protocol)
	if err == nil && (!protocol.Valid() || config.IsPublicService(invocation.project.Config.Services[invocation.service])) {
		err = publisherCLIError("configured service is not private")
	}
	return resolvedPrivateInvocation{invocation, protocol}, err
}

// runNamedPublish acquires a configured service through the project owner. the
// parent CLI resolves project/config flags and calls this for named services.
// replacement owners are rediscovered and receive a fresh lease; an old owner
// capability or registration is never replayed against the replacement.
func runNamedPublish(ctx context.Context, invocation resolvedNamedInvocation, stateDir string, output *publishOutput) (result error) {
	ctx, finishStartup := observability.ClientOperation(ctx, "client.publish.startup")
	defer func() { finishStartup(result) }()
	project, name := invocation.project, invocation.service
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
		return ensureRuntimeOwner(ctx, project, root)
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
					return publisherCLIError("the current local publisher uses another configuration or owns this service; stop it before publishing with these settings")
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
