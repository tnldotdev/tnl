package invocation

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"time"

	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/app"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type EnrolledSelection struct{ EnrollmentKey, PublisherID, PublisherFile string }

func PublisherFileServer(selected, path string) (string, error) {
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

// runEnrolledPublish uses only its scoped identity for URL and run operations.
func PublishEnrolled(ctx context.Context, flags EnrolledOptions, selection EnrolledSelection, output *Presentation, input io.Reader) (result error) {
	project := projectConfiguration{Project: flags.Project, targetResolver: flags.Resolver}
	selected := 0
	for _, value := range []string{selection.EnrollmentKey, selection.PublisherID, selection.PublisherFile} {
		if value != "" {
			selected++
		}
	}
	if selected != 1 || flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo {
		return failure.Wrap("select scoped publisher", failure.PublisherSelectionInvalid, errors.New("conflicting selection"))
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
		secret, err := EnrollmentKeyInput(selection.EnrollmentKey, input)
		if err != nil {
			return err
		}
		native, identity, err = nativeauth.EnrollNative(ctx, profile, control, authority, secret)
		if err != nil {
			if flags.Enrolled && (errors.Is(err, authorityclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrNotFound)) {
				return failure.Wrap("enroll publication", failure.PublisherEnrollmentRequired, err)
			}
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
	if flags.Enrolled && identity.Kind != authorityv1.SavedUrl {
		return nativeauth.ErrScope
	}
	if identity.Kind == authorityv1.PrivateService {
		if flags.Service != "" && config.IsPublicService(project.Config.Services[flags.Service]) {
			return failure.Wrap("select enrolled service", failure.PublisherGrantMismatch, errors.New("grant is private"))
		}
		service, err := native.SavedPrivateService(ctx)
		if err != nil {
			return err
		}
		if flags.Protocol != "" && flags.Protocol != string(service.Protocol) {
			return failure.Wrap("select enrolled protocol", failure.PublisherGrantMismatch, errors.New("protocol differs from private service"))
		}
		if output.Delegated != nil {
			output.Delegated()
		}
		private := PrivateOptions{PublicOptions: flags.PublicOptions, Protocol: string(service.Protocol), ConfiguredPrivate: true, TargetTLS: flags.TargetTLS, PublisherFile: selection.PublisherFile, PublisherID: identity.ClientId, EnrollmentInput: input}
		private.ServerURL = server
		if private.PublisherFile != "" {
			private.PublisherID = ""
		}
		if flags.SelectPrivate != nil {
			private.Limits, err = flags.SelectPrivate(service.Protocol)
			if err != nil {
				return err
			}
		}
		return PublishPrivate(ctx, private, flags.PrivatePresentation)
	}
	// a saved-URL grant returns its exact URL; namespace grants allocate one
	// HTTP URL per invocation and remove that same allocation after drain.
	route, err := native.SavedURL(ctx)
	if errors.Is(err, nativeauth.ErrScope) {
		if flags.Protocol != "" && flags.Protocol != "http" || flags.TargetTLSName != "" {
			return failure.Wrap("select namespace target", failure.PublisherNamespaceOptions, errors.New("unsupported namespace options"))
		}
		target, err := targetplan.NormalizePublicAddress(flags.Target, controlv1.Http)
		if err != nil {
			return err
		}
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			return err
		}
		b := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: invocation, Target: target}
		policy, err := resolveVisitorAccess(ctx, control, flags.Access, flags.Anonymous, flags.IP)
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
	} else if flags.Ephemeral || flags.Anonymous || flags.Access != nil || len(flags.IP) > 0 {
		return failure.Wrap("select saved URL policy", failure.PublisherSavedPolicy, errors.New("saved policy overrides supplied"))
	}
	if route.Purpose != controlv1.App || !route.ServiceProtocol.Valid() {
		return failure.Wrap("read enrolled public URL", failure.ServerResponseInvalid, errors.New("control returned an unsupported saved URL"))
	}
	if flags.Protocol != "" && flags.Protocol != string(route.ServiceProtocol) {
		return failure.Wrap("select enrolled protocol", failure.PublisherGrantMismatch, errors.New("protocol differs from public URL"))
	}
	if flags.SelectProtocol != nil {
		flags.Limits, err = flags.SelectProtocol(route.ServiceProtocol)
		if err != nil {
			return err
		}
	}
	target, err := targetplan.EnrolledAddress(route, flags.Target)
	if err != nil {
		return err
	}
	if flags.Enrolled && route.Ephemeral {
		return nativeauth.ErrScope
	}
	if flags.Enrolled {
		if err := profile.SelectPublisherIdentity(ctx, "job", RetainedScope(flags.Target), identity.ClientId); err != nil {
			return err
		}
	}
	options, err := localproxy.TargetOptionsForCA(flags.TargetCAFile, flags.ProjectRoot)
	if err != nil {
		return err
	}
	options.ServerName = flags.TargetTLSName
	if flags.ProjectRoot == "" {
		flags.ProjectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	tunnel, err := database.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Target: target, ServiceProtocol: route.ServiceProtocol, Project: flags.ProjectRoot, Service: flags.Service})
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
		output.configureBrowser(false)
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
	traffic, err := config.ResolveTrafficSelection(flags.WorkLimits)
	if err != nil {
		return err
	}
	native, err = native.WithTraffic(traffic)
	if err != nil {
		return err
	}
	cfg := publisher.Config{Control: native, ControlURL: server, State: profile, TeamID: route.TeamId, DomainID: route.DomainId, MembershipID: membership, PolicyRevision: uint64(route.PolicyRevision), PublicURLScope: route.PublicUrlScope, Purpose: route.Purpose, Hostname: route.CanonicalHostname, Target: target, AllowedIPPrefixes: prefixes, ServiceProtocol: route.ServiceProtocol, TargetTLSName: flags.TargetTLSName, TargetOptions: options, PreserveSavedURLTarget: route.Target == "", Limits: flags.Limits, InspectionMode: inspection.Mode(flags.InspectionMode), QUICConnector: muxsession.QUICConnector{TLSConfig: transportTLS}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: transportTLS}}
	if flags.Enrolled {
		discovery, err := control.Discovery(ctx)
		if err != nil {
			return err
		}
		cfg.BrowserLoginAvailable = discovery.BrowserLoginAvailable != nil && *discovery.BrowserLoginAvailable
	}
	cfg.PublisherID = native.PublisherID()
	if route.Ephemeral {
		cfg.Ephemeral = true
		cfg.AllocatedPublicURL = &route
	}
	recorder, err := NewInspectionRecorder(ctx, tunnel, flags.ProjectRoot, flags.Service, flags.InspectionMode, flags.Inspection)
	if err != nil {
		return err
	}
	defer recorder.Close()
	cfg.ObserveSummary = app.SummaryObservation(recorder)
	cfg.Mounts, err = ProjectMounts(project.Project, flags.Service, nil, flags.Resolver)
	if err != nil {
		return err
	}
	if route.ServiceProtocol != controlv1.Http && len(cfg.Mounts) > 0 {
		return failure.Wrap("select enrolled mounts", failure.PublisherGrantMismatch, errors.New("TCP publication has HTTP path mounts"))
	}
	cfg.Logf = output.Logf
	cfg.Observe = func(event publisher.Event) error { return output.publisherEvent(ctx, tunnel, server, event) }
	if flags.Enrolled {
		publisherjob.VerifyPublicationReadiness(ctx, &cfg, flags.ReadinessPath)
	}
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
