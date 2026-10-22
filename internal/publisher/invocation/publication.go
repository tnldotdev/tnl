package invocation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func PublishHTTP(ctx context.Context, flags PublicOptions, output *Presentation) (result error) {
	protocol := controlv1.Http
	project := projectConfiguration{Project: flags.Project, targetResolver: flags.Resolver}
	var err error
	var localDemo *demo.Server
	if flags.Demo {
		localDemo, err = demo.Start(output.DemoPing)
		if err != nil {
			return failure.Wrap("start local demo", failure.DemoLocalServiceUnavailable, err)
		}
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result = errors.Join(result, localDemo.Close(closeCtx))
		}()
		flags.Target = localDemo.Target()
		output.setDemo()
	}
	target, err := target.NormalizePublicAddress(flags.Target, protocol)
	if err != nil {
		return err
	}
	targetOptions, err := publisherproxy.TargetOptionsForCA(flags.TargetCAFile, flags.ProjectRoot)
	if err != nil {
		return err
	}
	if protocol == controlv1.Http {
		targetOptions.ServerName = flags.TargetTLSName
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	var oauthHostname string
	if !flags.Demo {
		if err := auth.RequireSignInOutsideDemo(ctx, state, serverURL, flags.AccessToken); err != nil {
			return err
		}
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target, ServiceProtocol: protocol,
		Project: flags.ProjectRoot, Service: flags.Service,
	})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finishCtx, result))
	}()
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if protocol == controlv1.Http {
		if err := publisherproxy.PreflightWithOptions(ctx, target, targetOptions); err != nil {
			return err
		}
	}
	var guest *clientstate.GuestSession
	if flags.Demo {
		guest, err = guestForDemo(ctx, state, serverURL, flags)
		if err != nil {
			return err
		}
		if guest != nil {
			output.setGuestDemo()
			localDemo.SetGuest()
		}
		if guest == nil {
			label := make([]byte, 4)
			if _, err := rand.Read(label); err != nil {
				return err
			}
			flags.Name = "demo-" + hex.EncodeToString(label)
		}
	}
	accessToken := flags.AccessToken
	if guest != nil {
		accessToken = guest.AccessToken
	}
	authenticated, err := flags.Authenticate(ctx, state, serverURL, accessToken)
	if err != nil {
		return err
	}
	if protocol == controlv1.Http {
		output.configureBrowser(authenticated.Discovery.DnsAutomation)
	}
	policy, err := resolveVisitorAccess(ctx, authenticated.Control, flags.Access, flags.Anonymous, flags.IP)
	if err != nil {
		return err
	}
	if guest != nil {
		// guest publication remains bound to its issuing IP. control discards
		// that prefix after checking it, so browser visits use the guest link.
		guestPrefixes, sourceErr := AccessIPPrefixes(ctx, authenticated.Control, []string{"current"})
		if sourceErr != nil {
			return sourceErr
		}
		policy.prefixes = guestPrefixes
	}
	if guest != nil {
		allocated, err := authenticated.Control.AllocateGuestDemoNumber(ctx)
		if err != nil {
			return err
		}
		flags.Name = "demo-" + strconv.FormatInt(allocated.Number, 10)
	}
	var services publisherServices
	if guest != nil {
		services, err = guestPublisherServices(ctx, state, serverURL, flags.Name, *guest, authenticated.Control)
	} else {
		services, err = preparePublisherServices(
			ctx, state, serverURL, flags.PublicURL, flags.Name, flags.Domain, flags.SelectedTeam, flags.Ephemeral, authenticated,
		)
	}
	if err != nil {
		return err
	}
	integrationGroup := ""
	if protocol == controlv1.Http && !flags.Demo && (project.Config.OAuth || len(project.Config.Webhooks) != 0 || len(project.Config.Aliases) != 0) {
		if project.Root == "" {
			worktree, resolveErr := clientproject.ResolveWorktree(ctx, flags.ProjectRoot)
			if resolveErr != nil {
				return resolveErr
			}
			project.Project = clientproject.Project{Root: flags.ProjectRoot, Worktree: worktree}
		}
		integrationGroup = projectIntegrationGroup(project.Project, services.namespace)
		if err := tunnel.SetIntegrationGroup(ctx, integrationGroup); err != nil {
			return err
		}
	}
	if protocol == controlv1.Http && !flags.Demo && project.Config.OAuth {
		oauth, oauthServices, resolveErr := projectOAuthPublisher(ctx, state, project.Project, serverURL, flags.SelectedTeam, authenticated)
		if resolveErr != nil {
			return resolveErr
		}
		stopCallbacks := startOAuthIntegrationURL(ctx, state, oauthServices, oauth, tunnel, output, telemetryReporter(output.Observe))
		defer stopCallbacks()
		oauthHostname = oauth.Hostname
	}
	if protocol == controlv1.Http && !flags.Demo && len(project.Config.Webhooks) > 0 {
		stopWebhooks := startWebhookIntegrationURL(ctx, state, services, project.Project, tunnel, flags.Service, integrationGroup, output, telemetryReporter(output.Observe))
		defer stopWebhooks()
	}
	publisherConfig := services.config(target, policy.prefixes, flags.Limits)
	if policy.explicit {
		publisherConfig.AccessMode = policy.access
	}
	publisherConfig.ServiceProtocol = protocol
	if protocol != controlv1.Http {
		publisherConfig.TargetTLSName = flags.TargetTLSName
	}
	publisherConfig.TargetOptions = targetOptions
	recorder, err := NewInspectionRecorder(ctx, tunnel, flags.ProjectRoot, flags.Service, flags.InspectionMode, flags.Inspection)
	if err != nil {
		return err
	}
	defer recorder.Close()
	publisherConfig.ObserveSummary = SummaryObservation(recorder)
	publisherConfig.InspectionMode = inspection.Mode(flags.InspectionMode)
	publisherConfig.OnWarning = publishWarning(tunnel, output)
	if oauthHostname != "" {
		publisherConfig.ObserveResponse = integrations.Observer(state, serverURL, oauthHostname, integrationGroup, tunnel.ID())
	}
	publisherConfig.ControlURL = authenticated.ServerEndpoint
	publisherConfig.BrowserLoginAvailable = authenticated.Discovery.BrowserLoginAvailable != nil && *authenticated.Discovery.BrowserLoginAvailable
	if flags.Demo {
		publisherConfig.Demo, publisherConfig.Feedback, publisherConfig.Service = true, true, "demo"
		if guest != nil {
			publisherConfig.Purpose = controlv1.Demo
		}
	}
	publisherConfig.Mounts, err = ProjectMounts(project.Project, flags.Service, nil, flags.Resolver)
	if err != nil {
		return err
	}
	if protocol != controlv1.Http && len(publisherConfig.Mounts) != 0 {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("TCP public URLs cannot use HTTP path mounts"))
	}
	publisherConfig.Logf = output.Logf
	cleanup, err := selectForegroundPublisher(ctx, state, services, &publisherConfig, guest)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, cleanup()) }()
	publisherConfig.Observe = func(event publisher.Event) error {
		if guest != nil && event.Type == publisher.EventPublicURLAssigned {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return err
			}
			fingerprint := sha256.Sum256(secret)
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return err
			}
			share, err := authenticated.Control.CreateURLShare(ctx, key, controlv1.CreateShareRequest{
				PublicUrlIds: []string{event.PublicURLID}, SecretFingerprint: hex.EncodeToString(fingerprint[:]), ExpiresAt: guest.ExpiresAt,
			})
			if err != nil {
				return fmt.Errorf("create guest share: %w", err)
			}
			if share.Scope != controlv1.ShareScopeGuest || len(share.PublicUrlIds) != 1 || share.PublicUrlIds[0] != event.PublicURLID {
				return failure.Wrap("create guest share", failure.ServerResponseInvalid, errors.New("server returned a share for another public URL"))
			}
			output.setGuestShare(share.Id + "." + base64.RawURLEncoding.EncodeToString(secret))
		}
		if localDemo != nil && event.Type == publisher.EventReady {
			localDemo.SetPublicURL(event.PublicURL)
		}
		return output.publisherEvent(ctx, tunnel, serverURL, event)
	}
	if protocol == controlv1.Http && !flags.Demo && len(project.Config.Aliases) != 0 {
		stopAliases := startProjectAliases(ctx, state, project, flags.Service, flags.SelectedTeam, services, publisherConfig, integrationGroup, tunnel, output)
		defer stopAliases()
	}
	err = publisher.Run(ctx, publisherConfig)
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return err
	}
	return output.stopped()
}
