package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type enrolledPublishSelection struct{ EnrollmentKey, PublisherID, PublisherFile string }

func publisherFileServer(selected, path string) (string, error) {
	file, err := credentialfile.Read(path)
	if err != nil {
		return "", err
	}
	if selected != "" {
		server, err := naming.CanonicalControlURL(selected)
		if err != nil || server != file.ControlURL {
			return "", nativeauth.ErrScope
		}
	}
	return file.ControlURL, nil
}

var _ publisher.PublicURLControlClient = (*nativeauth.Native)(nil)

func enrollmentKeyInput(value string, input io.Reader) (string, error) {
	if value == "-" {
		b, err := io.ReadAll(io.LimitReader(input, 257))
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(b))
	}
	if len(value) == 0 || len(value) > 256 || strings.ContainsAny(value, " \t\r\n") {
		return "", publisherCLIError("pass one enrollment key or --enroll-key - to read stdin")
	}
	return value, nil
}

func enrolledTarget(route controlv1.PublicURL, selected string) (string, error) {
	if route.ServiceProtocol != controlv1.Http {
		if route.Target != "" {
			return "", failure.Wrap("read enrolled URL target", failure.ServerResponseInvalid, errors.New("control returned a private TCP target"))
		}
		return normalizePublishTarget(selected, route.ServiceProtocol)
	}
	if selected == "" {
		selected = route.Target
	}
	target, err := normalizePublishTarget(selected, controlv1.Http)
	if err != nil {
		return "", err
	}
	if route.Target != "" && route.Target != target {
		return "", publisherCLIError("the HTTP target differs from the saved public URL")
	}
	return target, nil
}

// runEnrolledPublish uses only its scoped identity for URL and run operations.
func runEnrolledPublish(ctx context.Context, flags publishCommand, selection enrolledPublishSelection, output *publishOutput, telemetry telemetryReporter, input io.Reader) (result error) {
	selected := 0
	for _, value := range []string{selection.EnrollmentKey, selection.PublisherID, selection.PublisherFile} {
		if value != "" {
			selected++
		}
	}
	if selected != 1 || flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo {
		return publisherCLIError("select one enrollment key, publisher identity, or publisher file; its grant selects the public URL scope")
	}
	if selection.PublisherFile != "" {
		f, err := credentialfile.Read(selection.PublisherFile)
		if err != nil {
			return err
		}
		if flags.ServerURL != "" {
			server, err := naming.CanonicalControlURL(flags.ServerURL)
			if err != nil || server != f.ControlURL {
				return nativeauth.ErrScope
			}
		}
		flags.ServerURL = f.ControlURL
	}
	server, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer database.Close()
	profile, err := database.Server(ctx, server)
	if err != nil {
		return err
	}
	control, err := controlclient.New(server, nil, "")
	if err != nil {
		return err
	}
	authority, err := authorityclient.New(server, nil, "")
	if err != nil {
		return err
	}
	var native *nativeauth.Native
	var identity authorityv1.PublisherEnrollmentResult
	if selection.EnrollmentKey != "" {
		secret, err := enrollmentKeyInput(selection.EnrollmentKey, input)
		if err != nil {
			return err
		}
		native, identity, err = nativeauth.EnrollNative(ctx, profile, control, authority, secret)
		if err != nil {
			return err
		}
	} else if selection.PublisherID != "" {
		native, identity, err = nativeauth.LoadNative(ctx, profile, control, authority, selection.PublisherID)
		if err != nil {
			return err
		}
	} else {
		file, err := credentialfile.Read(selection.PublisherFile)
		if err != nil {
			return err
		}
		identity, _, err = file.Validate()
		if err != nil {
			return err
		}
		native, err = nativeauth.LoadFile(selection.PublisherFile, server, control, authority)
		if err != nil {
			return err
		}
	}
	if identity.Kind == authorityv1.PrivateService {
		if flags.Service != "" && config.IsPublicService(flags.project.Config.Services[flags.Service]) {
			return publisherCLIError("the publisher grant is private; select a configured service without publicURL")
		}
		service, err := native.SavedPrivateService(ctx)
		if err != nil {
			return err
		}
		if flags.Protocol != "" && flags.Protocol != string(service.Protocol) {
			return publisherCLIError("--protocol differs from the approved private service")
		}
		flags.Protocol = string(service.Protocol)
		flags.privateService = true
		output.delegatedLifecycle = true
		flags.EnrollmentKey = ""
		if flags.PublisherFile == "" {
			flags.PublisherID = identity.ClientId
		}
		flags.ServerURL = server
		return runPrivatePublish(ctx, flags, output.stdout, output.stderr)
	}
	// a saved-URL grant returns its exact URL; namespace grants allocate one
	// HTTP URL per invocation and remove that same allocation after drain.
	route, err := native.SavedURL(ctx)
	if errors.Is(err, nativeauth.ErrScope) {
		if flags.Protocol != "" && flags.Protocol != "http" || flags.TargetTLSName != "" {
			return publisherCLIError("namespace publication requires an HTTP target")
		}
		target, err := normalizePublishTarget(flags.Target, controlv1.Http)
		if err != nil {
			return err
		}
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			return err
		}
		b := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: invocation, Target: target}
		policy, err := resolveVisitorAccess(ctx, control, flags.access, flags.Anonymous, flags.IP)
		if err != nil {
			return err
		}
		if policy.explicit {
			b.AccessMode = &policy.access
			b.Ip = &policy.prefixes
		}
		route, err = native.Allocate(ctx, b)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := native.DeletePublicURL(cleanup, route.Id); err != nil && !errors.Is(err, controlclient.ErrNotFound) {
				result = errors.Join(result, err)
			}
		}()
	} else if err != nil {
		return err
	} else if flags.Ephemeral || flags.Anonymous || flags.access != nil || len(flags.IP) > 0 {
		return publisherCLIError("the saved URL sets visitor policy and lifecycle")
	}
	if route.Purpose != controlv1.App || !route.ServiceProtocol.Valid() {
		return failure.Wrap("read enrolled public URL", failure.ServerResponseInvalid, errors.New("control returned an unsupported saved URL"))
	}
	if flags.Protocol != "" && flags.Protocol != string(route.ServiceProtocol) {
		return publisherCLIError("--protocol differs from the saved public URL")
	}
	if err := selectPublishInspection(&flags, route.ServiceProtocol); err != nil {
		return err
	}
	if err := applyProtocolLimits(&flags.tunnelFlags, string(route.ServiceProtocol)); err != nil {
		return err
	}
	if err := validateTCPPublishOptions(flags, route.ServiceProtocol); err != nil {
		return err
	}
	target, err := enrolledTarget(route, flags.Target)
	if err != nil {
		return err
	}
	options, err := targetOptionsForCA(flags.TargetCAFile, flags.projectRoot)
	if err != nil {
		return err
	}
	if flags.projectRoot == "" {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	tunnel, err := database.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Target: target, ServiceProtocol: route.ServiceProtocol, Project: flags.projectRoot, Service: flags.Service})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finish, result))
	}()
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if route.ServiceProtocol == controlv1.Http {
		if err := localproxy.PreflightWithOptions(ctx, target, options); err != nil {
			return err
		}
		output.openURL = browserOpener(ctx, flags.Open, false)
	}
	membership := ""
	if route.MembershipId != nil {
		membership = *route.MembershipId
	}
	prefixes := []string{}
	if route.AllowedIpPrefixes != nil {
		prefixes = slices.Clone(*route.AllowedIpPrefixes)
	}
	transportTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	traffic, err := config.ResolveTrafficSelection(flags.workLimits)
	if err != nil {
		return err
	}
	native, err = native.WithTraffic(traffic)
	if err != nil {
		return err
	}
	cfg := publisher.Config{Control: native, ControlURL: server, State: profile, TeamID: route.TeamId, DomainID: route.DomainId, MembershipID: membership, PolicyRevision: uint64(route.PolicyRevision), PublicURLScope: route.PublicUrlScope, Purpose: route.Purpose, Hostname: route.CanonicalHostname, Target: target, AllowedIPPrefixes: prefixes, ServiceProtocol: route.ServiceProtocol, TargetTLSName: flags.TargetTLSName, TargetOptions: options, PreserveSavedURLTarget: route.Target == "", Limits: flags.limits(), InspectionMode: inspection.Mode(flags.InspectionMode), QUICConnector: muxsession.QUICConnector{TLSConfig: transportTLS}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: transportTLS}}
	cfg.PublisherID = native.PublisherID()
	if route.Ephemeral {
		cfg.Ephemeral = true
		cfg.AllocatedPublicURL = &route
	}
	recorder, err := newInspectionRecorder(ctx, tunnel, flags.projectRoot, flags.Service, flags.InspectionMode, flags.inspection)
	if err != nil {
		return err
	}
	defer recorder.Close()
	cfg.ObserveSummary = enrolledSummaryObservation(recorder)
	cfg.Mounts, err = resolveProjectMounts(flags.project, flags.Service)
	if err != nil {
		return err
	}
	if route.ServiceProtocol != controlv1.Http && len(cfg.Mounts) > 0 {
		return publisherCLIError("TCP public URLs cannot use HTTP path mounts")
	}
	cfg.Logf = output.logf
	cfg.Observe = withTelemetryObserver(telemetry, telemetryPublish, server, nil, func(event publisher.Event) error { return handlePublisherEvent(ctx, tunnel, output, event) })
	stopRuntime, err := startDeployedPublisher(ctx, native, server)
	if err != nil {
		return err
	}
	defer stopRuntime()
	if err := publisher.Run(ctx, cfg); err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return err
	}
	return output.stopped()
}

func enrolledSummaryObservation(recorder *clientstate.InspectionRecorder) inspection.Observer {
	if recorder == nil {
		return nil
	}
	return func(s inspection.Summary) {
		recorder.Observe(clientstate.InspectionRecord{Protocol: controlv1.PublicURLServiceProtocol(s.Protocol), ReceivedAt: s.ReceivedAt, Method: s.Method, Path: s.Path, Status: s.Status, DurationMS: s.Duration.Milliseconds(), Origin: s.Origin, Operation: s.Operation, Result: s.Result, RedisCommand: s.Command, SQLState: s.SQLState, Rows: s.Rows, ResultSets: int64(s.ResultSets), MySQLErrorCode: int64(s.MySQLErrorCode)})
	}
}
