package main

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// scopedPublishControl makes credential-backed publishing unable to mutate URL settings.
type scopedPublishControl struct {
	*controlclient.Client
	credential credentials.PublicURLPublishCredential
	urlID      string
}

var _ publisher.PublicURLControlClient = (*scopedPublishControl)(nil)

func (c *scopedPublishControl) GetPublicURLByHostname(ctx context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	route, err := c.Client.PublicURLForPublishCredential(ctx, c.credential)
	if err != nil {
		return route, err
	}
	if route.Id != c.urlID || route.TeamId != teamID || route.CanonicalHostname != hostname {
		return controlv1.PublicURL{}, controlclient.ErrStatusConflict
	}
	return route, nil
}

func (c *scopedPublishControl) CreatePublishRun(ctx context.Context, publicURLID, key string) (controlv1.PublishRunSetup, error) {
	if publicURLID != c.urlID {
		return controlv1.PublishRunSetup{}, controlclient.ErrStatusConflict
	}
	return c.Client.CreatePublishRunWithCredential(ctx, publicURLID, key, c.credential)
}

func (*scopedPublishControl) CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, controlclient.ErrStatusConflict
}

func (*scopedPublishControl) UpdatePublicURL(context.Context, string, controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, controlclient.ErrStatusConflict
}

func (*scopedPublishControl) DeletePublicURL(context.Context, string) error {
	return controlclient.ErrStatusConflict
}

func runScopedPublish(ctx context.Context, flags publishCommand, output *publishOutput, telemetry telemetryReporter) (result error) {
	if flags.AccessToken != "" || flags.PublicURL == "" || flags.Name != "" || flags.Domain != "" || flags.Team != "" ||
		flags.Ephemeral || flags.AllowAllIPs || len(flags.AllowIP) != 0 {
		return failure.Wrap("validate scoped publish options", failure.InvalidTunnelFlags, errors.New("a scoped publish credential requires --public-url and cannot change saved URL settings"))
	}
	if flags.project.Config.OAuth || len(flags.project.Config.Webhooks) != 0 || len(flags.project.Config.Aliases) != 0 {
		return failure.Wrap("validate scoped publish project", failure.InvalidTunnelFlags, errors.New("project integration URLs require a signed-in tnl session"))
	}
	target, err := localproxy.NormalizeTarget(flags.Target)
	if err != nil {
		return err
	}
	targetOptions, err := targetOptionsForCA(flags.TargetCAFile, flags.projectRoot)
	if err != nil {
		return err
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	profile, err := state.Server(ctx, serverURL)
	if err != nil {
		return err
	}
	client, err := controlclient.New(serverURL, nil, "")
	if err != nil {
		return err
	}
	credential := credentials.PublicURLPublishCredential(flags.PublishCredential)
	route, err := client.PublicURLForPublishCredential(ctx, credential)
	if err != nil {
		return classifyScopedPublishError(err)
	}
	if flags.PublicURL != "https://"+route.CanonicalHostname || target != route.Target || route.Purpose != controlv1.App || route.Ephemeral || route.LifecycleState != controlv1.Enabled {
		return failure.Wrap("validate scoped publish target", failure.PublishCredentialMismatch, errors.New("credential is bound to another public URL or target"))
	}
	if flags.projectRoot == "" {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target,
		Project: flags.projectRoot, Service: flags.Service,
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
	if err := localproxy.PreflightWithOptions(ctx, target, targetOptions); err != nil {
		return err
	}
	output.openURL = browserOpener(ctx, flags.Open, false)
	publicURLScope := route.PublicUrlScope
	membershipID := ""
	if route.MembershipId != nil {
		membershipID = *route.MembershipId
	}
	allowed := []string{}
	if route.AllowedIpPrefixes != nil {
		allowed = slices.Clone(*route.AllowedIpPrefixes)
	}
	if route.PolicyRevision < 1 {
		return errors.New("control returned a public URL without a policy revision")
	}
	connectionTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	publisherConfig := publisher.Config{
		Control:    &scopedPublishControl{Client: client, credential: credential, urlID: route.Id},
		ControlURL: serverURL, State: profile,
		TeamID: route.TeamId, DomainID: route.DomainId, MembershipID: membershipID,
		PolicyRevision: uint64(route.PolicyRevision), PublicURLScope: publicURLScope, Purpose: controlv1.App,
		Hostname: route.CanonicalHostname, Target: target, AllowedIPPrefixes: allowed,
		TargetOptions: targetOptions,
		RequestLimit:  flags.requestLimit(), RequestInspection: flags.RequestInspection,
		QUICConnector: muxsession.QUICConnector{TLSConfig: connectionTLS},
		TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: connectionTLS},
	}
	recorder, err := newRequestRecorder(ctx, tunnel, flags.projectRoot, flags.Service)
	if err != nil {
		return err
	}
	defer recorder.Close()
	publisherConfig.ObserveRequest = requestObservation(recorder)
	publisherConfig.Mounts, err = resolveProjectMounts(flags.project, flags.Service)
	if err != nil {
		return err
	}
	publisherConfig.Logf = output.logf
	publisherConfig.Observe = withTelemetryObserver(telemetry, telemetryPublish, serverURL, nil, func(event publisher.Event) error {
		return handlePublisherEvent(ctx, tunnel, output, event)
	})
	err = publisher.Run(ctx, publisherConfig)
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return classifyScopedPublishError(err)
	}
	return output.stopped()
}

func classifyScopedPublishError(err error) error {
	if errors.Is(err, controlclient.ErrUnauthenticated) {
		return failure.Wrap("authenticate scoped publication", failure.PublishCredentialRejected, err)
	}
	return err
}
