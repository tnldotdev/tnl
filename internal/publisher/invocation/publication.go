package invocation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheradhoc "github.com/tnldotdev/tnl/internal/publisher/adhoc"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func PublishHTTP(ctx context.Context, flags PublicOptions, output *Presentation) (result error) {
	telemetry := flags.Telemetry.BeginScope("publisher")
	defer telemetry.Close()
	project := projectConfiguration{Project: flags.Project, targetResolver: flags.Resolver}
	var state *clientstate.Database
	var tunnel *clientstate.Tunnel
	var recorder *clientstate.InspectionRecorder
	var localDemo *demo.Server
	var cleanup func() error
	ctx, shutdownDeadline, joinShutdown := publicationShutdown(ctx)
	defer joinShutdown()
	var stopIntegrations func()
	// the service operation joins its workers before returning. drain its
	// observations and remove temporary state before finishing this journal.
	defer func() {
		finish, cancel := context.WithDeadline(context.WithoutCancel(ctx), shutdownDeadline())
		defer cancel()
		if stopIntegrations != nil {
			stopIntegrations()
		}
		if recorder != nil {
			result = errors.Join(result, recorder.Close(finish))
		}
		if cleanup != nil {
			result = errors.Join(result, cleanup())
		}
		if localDemo != nil {
			result = errors.Join(result, localDemo.Close(finish))
		}
		if tunnel != nil {
			result = errors.Join(result, tunnel.Finish(finish, result))
		}
		if state != nil {
			result = errors.Join(result, state.Close())
		}
	}()
	var err error
	if flags.Demo {
		localDemo, err = demo.Start(func(state demo.State) error {
			if output != nil && output.DemoPing != nil {
				if err := output.DemoPing(state); err != nil {
					return err
				}
			}
			telemetry.Demo()
			return nil
		})
		if err != nil {
			return failure.Wrap("start local demo", failure.DemoLocalServiceUnavailable, err)
		}
		flags.Target = localDemo.Target()
		output.setDemo()
	}
	address, err := targetsyntax.NormalizeTarget(flags.Target)
	if err != nil {
		return err
	}
	targetFlags := ServiceOptions{PublicOptions: flags}
	if strings.HasPrefix(address, "https://") {
		targetFlags.TargetTLS = new(true)
	}
	trust, err := CaptureServiceTargetTrust(ctx, targetFlags, controlv1.ServiceProtocolHTTP, address)
	if err != nil {
		return err
	}
	plan := targetplan.TargetPlan{Protocol: config.ProtocolHTTP, Target: address, Trust: trust}
	var server string
	server, state, err = resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	if !flags.Demo {
		if err := auth.RequireSignInOutsideDemo(ctx, state, server, flags.AccessToken); err != nil {
			return err
		}
	}
	var guest *clientstate.GuestSession
	if flags.Demo {
		guest, err = guestForDemo(ctx, state, server, flags)
		if err != nil {
			return err
		}
		if guest != nil {
			output.setGuestDemo()
			localDemo.SetGuest()
		} else {
			flags.Name, err = naming.RandomHostnameLabel()
			if err != nil {
				return err
			}
		}
	}
	profile, err := state.Server(ctx, server)
	if err != nil {
		return err
	}
	var native *publisheridentity.Native
	var saved controlv1.Service
	var cfg publisherservice.RunConfig
	if guest != nil {
		output.configureBrowser(false)
		native, saved, cleanup, err = prepareGuestDemoService(ctx, state, server, *guest, flags, address, shutdownDeadline)
		// cleanup is retained even if the allocation reply was lost.
		if err != nil {
			return err
		}
	} else {
		authenticated, err := flags.Authenticate(ctx, state, server, flags.AccessToken)
		if err != nil {
			return err
		}
		output.configureBrowser(authenticated.Discovery.DnsAutomation)
		policy, err := resolveVisitorAccess(ctx, authenticated.Control, flags.Access, flags.Anonymous, flags.IP)
		if err != nil {
			return err
		}
		services, err := preparePublisherServices(ctx, state, server, flags.PublicURL, flags.Name, flags.Domain, flags.SelectedTeam, flags.Ephemeral, authenticated)
		if err != nil {
			return err
		}
		if flags.Ephemeral {
			native, _, err = publisheridentity.EnsureNamespace(ctx, profile, authenticated.Control, authenticated.Authority, services.teamID, services.domainID, services.namespace)
			if err != nil {
				return err
			}
			invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				return err
			}
			targetTLS, err := foregroundTargetTLS(plan.Trust)
			if err != nil {
				return err
			}
			options := publisheradhoc.Options{State: profile, Publisher: native, ControlURL: server,
				InvocationID: invocation, Target: address, TargetTLS: targetTLS, AccessMode: policy.access, IP: policy.prefixes, Limits: flags.Limits}
			if flags.RequirePostQuantum != nil {
				options.RequirePostQuantum = *flags.RequirePostQuantum
			}
			prepared, err := publisheradhoc.Prepare(ctx, options)
			if prepared != nil {
				cleanup = func() error {
					finish, cancel := context.WithDeadline(context.Background(), shutdownDeadline())
					defer cancel()
					return prepared.Cleanup(finish)
				}
			}
			if err != nil {
				return err
			}
			native, saved, cfg = prepared.Publisher(), prepared.Service, prepared.Config
		} else {
			native, saved, plan, err = prepareForegroundService(ctx, services, flags, policy, plan)
			if err != nil {
				return err
			}
		}
	}
	if err := validateProfileService(saved); err != nil {
		return err
	}
	if saved.Protocol != controlv1.ServiceProtocolHTTP || !saved.Endpoint.Public {
		return publisheridentity.ErrScope
	}
	if err := publisheridentity.MatchServiceDeclaration(saved, "http", plan.Trust); err != nil {
		return failure.Wrap("match service declaration", failure.ServerConflict, err)
	}
	if flags.Service != "" && config.TargetType(project.Config.Services[flags.Service]) != "app" {
		plan.Project, plan.ProjectService = &project.Project, flags.Service
	}
	if err := plan.Normalize(); err != nil {
		return err
	}
	if err := targetplan.PreflightPrivate(ctx, plan); err != nil {
		return err
	}
	if saved.ExpiresAt != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *saved.ExpiresAt)
		defer cancel()
	}
	tunnel, err = state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Target: plan.Target,
		ServiceProtocol: saved.Protocol, ServiceID: saved.Id, Project: flags.ProjectRoot, Service: flags.Service,
	})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	if err := output.starting(tunnel.ID(), plan.Target); err != nil {
		return err
	}
	settings := flags.Inspection
	if flags.InspectionMode != "" {
		settings = config.MergeInspection(settings, &config.Inspection{Mode: &flags.InspectionMode})
	}
	inspection, err := config.ResolveInspection(settings, "http")
	if err != nil {
		return err
	}
	recorder, err = NewInspectionRecorder(ctx, tunnel, flags.ProjectRoot, flags.Service, config.InspectionMode(inspection.Mode), settings)
	if err != nil {
		return err
	}
	cfg.Control, cfg.State, cfg.Access = native, profile, native.Access
	cfg.ShutdownDeadline = shutdownDeadline
	cfg.PublisherIdentityID, cfg.PublisherGrantID, cfg.PublisherKeyID = native.PublisherIdentityID(), native.PublisherGrantID(), native.PublisherKeyID()
	cfg.ServiceID, cfg.Metadata = saved.Id, publisheridentity.ServiceMetadata(saved)
	cfg.Target, cfg.ProjectRoot, cfg.ProjectService = plan.Target, flags.ProjectRoot, flags.Service
	cfg.Telemetry, cfg.PreferredRegions = flags.Telemetry, slices.Clone(flags.PreferredRegions)
	if flags.TelemetryDisabled {
		cfg.Telemetry = nil
	}
	cfg.TransportTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.InspectionMode, cfg.ObserveSummary = inspection.Mode, SummaryObservation(recorder)
	cfg.Mounts, err = ProjectMounts(ctx, project.Project, flags.Service, nil, flags.Resolver)
	if err != nil {
		return err
	}
	if flags.Demo {
		cfg.Demo, cfg.Feedback, cfg.ProjectService = true, true, "demo"
		if guest != nil {
			trial, err := clientcontrol.New(server, nil, credentials.AccessToken(guest.AccessToken))
			if err != nil {
				return err
			}
			link, err := foregroundGuestShare(ctx, trial, saved, *guest)
			if err != nil {
				return err
			}
			output.setGuestShare(link)
		}
	} else {
		if project.Config.OAuth || len(project.Config.Webhooks) != 0 || len(project.Config.Aliases) != 0 {
			if project.Root == "" {
				worktree, err := clientproject.ResolveWorktree(ctx, flags.ProjectRoot)
				if err != nil {
					return err
				}
				project.Root, project.Worktree = flags.ProjectRoot, worktree
			}
			stopIntegrations, err = attachRuntimeIntegrations(ctx, state, project.Project, publisherapp.Service{Name: flags.Service, Target: plan.Target}, tunnel, &cfg)
			if err != nil {
				return err
			}
		}
	}
	if localDemo != nil {
		cfg.Ready = func() error {
			localDemo.SetPublicURL("https://" + saved.Endpoint.Hostname)
			return nil
		}
	}
	return RunServiceCLI(ctx, tunnel, saved, cfg, output, func(ctx context.Context, cfg publisherservice.RunConfig) error {
		return targetplan.PublishPrivate(ctx, plan, cfg, targetplan.TargetHooks{Resolver: flags.Resolver})
	})
}

type foregroundShareControl interface {
	CreateServiceShare(context.Context, string, controlv1.CreateShareRequest) (controlv1.ShareCreation, error)
}

func foregroundGuestShare(ctx context.Context, control foregroundShareControl, saved controlv1.Service, guest clientstate.GuestSession) (string, error) {
	if !opaqueid.Valid(guest.GuestID, opaqueid.GuestPrefix) || saved.GuestId != guest.GuestID || saved.TeamId != "" {
		return "", publisheridentity.ErrScope
	}
	expires := guest.ExpiresAt
	if saved.ExpiresAt != nil && saved.ExpiresAt.Before(expires) {
		expires = *saved.ExpiresAt
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return "", err
	}
	share, err := control.CreateServiceShare(ctx, key, controlv1.CreateShareRequest{
		ServiceIds: []string{saved.Id}, EntryServiceId: saved.Id, ExpiresAt: expires,
	})
	if err != nil {
		return "", fmt.Errorf("create guest share: %w", err)
	}
	if share.Share.Scope != controlv1.ShareScopeGuest || len(share.Share.ServiceIds) != 1 || share.Share.ServiceIds[0] != saved.Id ||
		share.Share.EntryServiceId != saved.Id || share.Share.GuestId != guest.GuestID || share.Share.TeamId != "" ||
		share.Share.CreatedByIdentityId != "" || share.Share.RevokedAt != nil ||
		!share.Share.ExpiresAt.After(time.Now()) || share.Share.ExpiresAt.After(expires) || share.Link == "" {
		return "", failure.Wrap("create guest share", failure.ServerResponseInvalid, errors.New("control returned another guest, service, scope, or expiration"))
	}
	return share.Link, nil
}
