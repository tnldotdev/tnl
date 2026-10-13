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
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
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

func (c *scopedPublishControl) CreatePublishRunWithTraffic(ctx context.Context, publicURLID, key string, traffic trafficlimits.Selection) (controlv1.PublishRunSetup, error) {
	return c.Client.CreatePublishRunWithCredentialTraffic(ctx, publicURLID, key, c.credential, traffic)
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
	if flags.AccessToken != "" || flags.Name != "" || flags.Domain != "" || flags.Team != "" ||
		flags.Ephemeral || flags.AllowAllIPs || len(flags.AllowIP) != 0 {
		return failure.Wrap("validate scoped publish options", failure.InvalidTunnelFlags, errors.New("a scoped publish credential cannot change saved URL settings"))
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
	selectedHostname := route.CanonicalHostname
	if flags.PublicURL != "" {
		selectedHostname, err = naming.ParseExactPublicURL(flags.PublicURL)
		if err != nil {
			return failure.Wrap("validate scoped publish public URL", failure.InvalidTunnelFlags, err)
		}
	}
	if route.Purpose != controlv1.App || route.Ephemeral || route.LifecycleState != controlv1.Enabled || selectedHostname != route.CanonicalHostname {
		return failure.Wrap("validate scoped publish target", failure.PublishCredentialMismatch, errors.New("credential is bound to another public URL or target"))
	}
	protocol := route.ServiceProtocol
	if protocol == "" {
		protocol = controlv1.Http
	}
	requestedProtocol, err := publishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if flags.Protocol != "" && requestedProtocol != protocol {
		return failure.Wrap("validate scoped publish protocol", failure.PublishCredentialMismatch,
			errors.New("protocol differs from the saved public URL"))
	}
	if !protocol.Valid() {
		return failure.Wrap("read scoped publish protocol", failure.ServerResponseInvalid,
			errors.New("control returned an invalid service protocol"))
	}
	if flags.Protocol == "" {
		effective, err := flags.project.EffectiveService(flags.Service)
		if err != nil {
			return err
		}
		if effective.Tunnel != nil {
			applyTunnelLimits(&flags.tunnelFlags, effective.Tunnel.Limits, string(protocol))
		}
		if err := validateTunnelFlags(flags.tunnelFlags); err != nil {
			return failure.Wrap("validate tunnel options", failure.InvalidTunnelFlags, err)
		}
	}
	if err := selectPublishInspection(&flags, protocol); err != nil {
		return err
	}
	traffic, err := flags.traffic()
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	if protocol == controlv1.Http && (flags.project.Config.OAuth || len(flags.project.Config.Webhooks) != 0 || len(flags.project.Config.Aliases) != 0) {
		return failure.Wrap("validate scoped publish project", failure.InvalidTunnelFlags, errors.New("project integration URLs require a signed-in tnl session"))
	}
	if err := validateTCPPublishOptions(flags, protocol); err != nil {
		return err
	}
	target, err := selectScopedPublishTargetForProtocol(route.Target, flags.Target, protocol)
	if err != nil {
		return err
	}
	targetOptions, err := targetOptionsForCA(flags.TargetCAFile, flags.projectRoot)
	if err != nil {
		return err
	}
	if flags.projectRoot == "" {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target, ServiceProtocol: protocol,
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
	if protocol == controlv1.Http {
		if err := localproxy.PreflightWithOptions(ctx, target, targetOptions); err != nil {
			return err
		}
	}
	if protocol == controlv1.Http {
		output.openURL = browserOpener(ctx, flags.Open, false)
	}
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
		Hostname: route.CanonicalHostname, Target: target, ResolveTarget: flags.resolveTarget, AllowedIPPrefixes: allowed,
		ServiceProtocol: protocol, TargetTLSName: flags.TargetTLSName, TargetTLS: flags.TargetTLS, VisitorTLSPassthrough: flags.VisitorTLSPassthrough,
		PreserveSavedURLTarget: route.Target == "",
		TargetOptions:          targetOptions,
		Limits:                 flags.limits(), Traffic: traffic, InspectionMode: flags.InspectionMode,
		QUICConnector: muxsession.QUICConnector{TLSConfig: connectionTLS},
		TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: connectionTLS},
	}
	recorder, err := newInspectionRecorder(ctx, tunnel, flags.projectRoot, flags.Service, flags.tunnelFlags)
	if err != nil {
		return err
	}
	defer recorder.Close()
	publisherConfig.ObserveRequest = httpObservation(recorder)
	if (protocol == controlv1.Mysql || protocol == controlv1.Postgres) && !flags.VisitorTLSPassthrough {
		publisherConfig.ObserveDatabase = sqlObservation(recorder)
	}
	if protocol == controlv1.Redis {
		publisherConfig.ObserveRedis = redisObservation(recorder)
	}
	publisherConfig.Mounts, err = resolveProjectMounts(flags.project, flags.Service)
	if err != nil {
		return err
	}
	if protocol != controlv1.Http && len(publisherConfig.Mounts) != 0 {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("TCP public URLs cannot use HTTP path mounts"))
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

func selectScopedPublishTarget(saved, selected string) (string, error) {
	if saved != "" {
		canonical, err := localproxy.NormalizeTarget(saved)
		if err != nil || canonical != saved {
			return "", failure.Wrap("read scoped publish target", failure.ServerResponseInvalid, errors.New("control returned an invalid saved target"))
		}
	}
	if selected == "" {
		if saved == "" {
			return "", failure.Wrap("select scoped publish target", failure.MissingTarget, errors.New("pass a target or set TNL_TARGET or publish.target"))
		}
		return saved, nil
	}
	target, err := localproxy.NormalizeTarget(selected)
	if err != nil {
		return "", err
	}
	if saved != "" && target != saved {
		return "", failure.Wrap("validate scoped publish target", failure.PublishCredentialMismatch, errors.New("target differs from the saved public URL"))
	}
	return target, nil
}

func selectScopedPublishTargetForProtocol(saved, selected string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	if protocol == controlv1.Http {
		return selectScopedPublishTarget(saved, selected)
	}
	if saved != "" {
		return "", failure.Wrap("read scoped publish target", failure.ServerResponseInvalid,
			errors.New("control returned a TCP target"))
	}
	if selected == "" {
		return "", failure.Wrap("select scoped publish target", failure.MissingTarget,
			errors.New("pass a TCP host:port or set TNL_TARGET"))
	}
	return normalizePublishTarget(selected, protocol)
}

func classifyScopedPublishError(err error) error {
	if errors.Is(err, controlclient.ErrUnauthenticated) {
		return failure.Wrap("authenticate scoped publication", failure.PublishCredentialRejected, err)
	}
	return err
}
