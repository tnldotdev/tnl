package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/adhoc"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisherauth"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func enrollmentKeyInput(value string, input io.Reader) (string, error) {
	if value == "-" {
		read, err := io.ReadAll(io.LimitReader(input, 257))
		if err != nil {
			return "", failure.Wrap("read publisher enrollment key", failure.InvalidTunnelFlags, err)
		}
		value = strings.TrimSpace(string(read))
	}
	if value == "" || len(value) > 256 || strings.ContainsAny(value, " \t\n\r") {
		return "", failure.Wrap("read publisher enrollment key", failure.InvalidTunnelFlags, errors.New("pass one enrollment key or --enroll-key - to read stdin"))
	}
	return value, nil
}

func runEnrolledPublish(ctx context.Context, flags publishCommand, output *publishOutput, telemetry telemetryReporter, input io.Reader) (result error) {
	if flags.Background {
		if err := validateBackgroundPublishOptions(flags); err != nil {
			return err
		}
	}
	if flags.Demo || flags.AccessToken != "" || flags.PublicURL != "" || flags.Name != "" || flags.Domain != "" {
		return failure.Wrap("validate publisher enrollment", failure.InvalidTunnelFlags,
			errors.New("an enrollment key selects the public URL scope"))
	}
	key, err := enrollmentKeyInput(flags.EnrollKey, input)
	if err != nil {
		return err
	}
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	auth, err := clientauth.PublisherClients(ctx, server, nil)
	if err != nil {
		return err
	}
	owner, err := publisherauth.Redeem(ctx, auth.PublisherControl, auth.PublisherAuthority, key)
	if err != nil {
		return err
	}
	if namespace, ok := owner.EnrolledNamespace(); ok {
		if flags.Background {
			return failure.Wrap("install namespace publisher", failure.InvalidTunnelFlags,
				errors.New("--bg requires an enrolled saved public URL"))
		}
		return runEnrolledAdHoc(ctx, flags, output, telemetry, state, auth, owner, namespace, server)
	}
	if flags.Ephemeral || len(flags.AllowIP) != 0 || flags.AllowAllIPs {
		return failure.Wrap("validate publisher enrollment", failure.InvalidTunnelFlags,
			errors.New("a saved public URL keeps the visitor policy selected at enrollment"))
	}
	route, err := owner.CurrentURL(ctx)
	if err != nil {
		return err
	}
	if route.Purpose != controlv1.App {
		return failure.Wrap("select enrolled public URL", failure.InvalidTunnelFlags,
			errors.New("publish --enroll-key needs a saved app public URL"))
	}
	protocol := route.ServiceProtocol
	if flags.Protocol != "" {
		selected, err := publishProtocol(flags.Protocol)
		if err != nil {
			return err
		}
		if selected != protocol {
			return failure.Wrap("select enrolled protocol", failure.InvalidTunnelFlags,
				errors.New("--protocol differs from the enrolled public URL"))
		}
	}
	target, err := selectEnrolledTarget(route, flags.Target)
	if err != nil {
		return err
	}
	targetOptions, err := targetOptionsForCA(flags.TargetCAFile, flags.projectRoot)
	if err != nil {
		return err
	}
	if protocol == controlv1.Http {
		if err := localproxy.PreflightWithOptions(ctx, target, targetOptions); err != nil {
			return err
		}
	}
	if flags.Background {
		identity, err := owner.InstalledIdentity()
		if err != nil {
			return err
		}
		return installBackgroundPublisher(ctx, localpublisher.ServiceJob{
			Server: server, PublicURLID: route.Id, Target: target,
			Protocol: route.ServiceProtocol, Identity: identity,
		}, output, route)
	}
	services, err := localpublisher.EnrolledServices(ctx, state, auth, route)
	if err != nil {
		return err
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Target: target,
		ServiceProtocol: protocol, Project: flags.projectRoot, Service: flags.Service,
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
	traffic, err := flags.traffic()
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	allowed := []string{}
	if route.AllowedIpPrefixes != nil {
		allowed = *route.AllowedIpPrefixes
	}
	configuration := services.Config(target, allowed, flags.limits(), traffic)
	configuration.Control = &publisherauth.RunControl{Client: auth.PublisherControl, Owner: owner}
	configuration.ServiceProtocol = protocol
	configuration.TargetOptions = targetOptions
	configuration.TargetTLS, configuration.TargetTLSName = flags.TargetTLS, flags.TargetTLSName
	configuration.VisitorTLSPassthrough = flags.VisitorTLSPassthrough
	configuration.PreserveSavedURLSettings = true
	configuration.ControlURL = auth.ServerEndpoint
	configuration.BrowserLoginAvailable = auth.Discovery.BrowserLoginAvailable != nil && *auth.Discovery.BrowserLoginAvailable
	configuration.InspectionMode = flags.InspectionMode
	recorder, err := newInspectionRecorder(ctx, tunnel, flags.projectRoot, flags.Service, flags.tunnelFlags)
	if err != nil {
		return err
	}
	defer recorder.Close()
	configuration.ObserveRequest = httpObservation(recorder)
	if (protocol == controlv1.Mysql || protocol == controlv1.Postgres) && !configuration.VisitorTLSPassthrough {
		configuration.ObserveDatabase = sqlObservation(recorder, flags.InspectionMode)
	}
	configuration.Logf = output.logf
	configuration.Observe = withTelemetryObserver(telemetry, telemetryPublish, server, nil, func(event publisher.Event) error {
		return handlePublisherEvent(ctx, tunnel, output, event)
	})
	err = publisher.Run(ctx, configuration)
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return err
	}
	return output.stopped()
}

func runEnrolledAdHoc(ctx context.Context, flags publishCommand, output *publishOutput, telemetry telemetryReporter,
	state *clientstate.Database, auth *clientauth.Client, owner *publisherauth.Owner, namespace publisherauth.Namespace, server string) (result error) {
	if flags.Protocol != "" && flags.Protocol != "http" || flags.TargetCAFile != "" || flags.TargetTLS || flags.VisitorTLSPassthrough {
		return failure.Wrap("validate namespace publisher", failure.InvalidTunnelFlags,
			errors.New("a namespace enrollment publishes an HTTP target"))
	}
	target, err := normalizePublishTarget(flags.Target, controlv1.Http)
	if err != nil {
		return err
	}
	if err := localproxy.PreflightWithOptions(ctx, target, localproxy.TargetOptions{}); err != nil {
		return err
	}
	invocationID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return err
	}
	traffic, err := flags.traffic()
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Target: target,
		ServiceProtocol: controlv1.Http, Project: flags.projectRoot, Service: flags.Service,
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
	output.openURL = browserOpener(ctx, flags.Open, auth.Discovery.DnsAutomation)
	scoped, err := state.Server(ctx, server)
	if err != nil {
		return err
	}
	err = adhoc.Run(ctx, adhoc.Options{
		ControlURL: auth.ServerEndpoint, State: scoped, Owner: owner, Namespace: namespace,
		InvocationID: invocationID, Target: target, AllowIP: flags.AllowIP, AllowAllIPs: flags.AllowAllIPs,
		Limits: flags.limits(), Traffic: traffic,
		Observe: withTelemetryObserver(telemetry, telemetryPublish, server, nil, func(event publisher.Event) error {
			return handlePublisherEvent(ctx, tunnel, output, event)
		}),
	})
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return err
	}
	return output.stopped()
}

func selectEnrolledTarget(route controlv1.PublicURL, input string) (string, error) {
	if input == "" {
		return "", failure.Wrap("select enrolled target", failure.MissingTarget, errors.New("pass the local target to publish"))
	}
	if !route.ServiceProtocol.Valid() {
		return "", failure.Wrap("select enrolled protocol", failure.ServerResponseInvalid, errors.New("saved public URL has an unknown protocol"))
	}
	target, err := normalizePublishTarget(input, route.ServiceProtocol)
	if err != nil {
		return "", err
	}
	if route.ServiceProtocol != controlv1.Http && route.Target != "" {
		return "", failure.Wrap("select enrolled TCP target", failure.ServerResponseInvalid, errors.New("TCP saved public URLs cannot store a private target"))
	}
	if route.ServiceProtocol == controlv1.Http && route.Target != "" && route.Target != target {
		return "", failure.Wrap("select enrolled target", failure.ServerConflict, errors.New("target differs from the saved public URL"))
	}
	return target, nil
}
