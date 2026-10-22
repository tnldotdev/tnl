package invocation

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type EnrolledSelection struct{ EnrollmentKey, PublisherIdentityID, PublisherCredentialFile string }

func PublisherCredentialFileServer(selected, path string) (string, error) {
	file, err := credentialfile.Read(path)
	if err != nil {
		return "", err
	}
	if selected != "" {
		server, err := naming.CanonicalControlURL(selected)
		if err != nil || server != file.ControlURL {
			return "", publisheridentity.ErrScope
		}
	}
	return file.ControlURL, nil
}

var _ publisher.PublicURLControlClient = (*publisheridentity.Native)(nil)

// runEnrolledPublish uses only its scoped identity for URL and run operations.
func PublishEnrolled(ctx context.Context, flags EnrolledOptions, selection EnrolledSelection, output *Presentation, input io.Reader) (result error) {
	project := projectConfiguration{Project: flags.Project, targetResolver: flags.Resolver}
	selected := 0
	for _, value := range []string{selection.EnrollmentKey, selection.PublisherIdentityID, selection.PublisherCredentialFile} {
		if value != "" {
			selected++
		}
	}
	if selected != 1 || flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo {
		return failure.Wrap("select scoped publisher", failure.PublisherSelectionInvalid, errors.New("conflicting selection"))
	}
	if selection.PublisherCredentialFile != "" {
		f, err := credentialfile.Read(selection.PublisherCredentialFile)
		if err != nil {
			return err
		}
		if flags.ServerURL != "" {
			server, err := naming.CanonicalControlURL(flags.ServerURL)
			if err != nil || server != f.ControlURL {
				return publisheridentity.ErrScope
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
	control, err := clientcontrol.New(server, nil, "")
	if err != nil {
		return err
	}
	authority, err := clientauthority.New(server, nil, "")
	if err != nil {
		return err
	}
	var native *publisheridentity.Native
	var identity authorityv1.PublisherEnrollmentResult
	if selection.EnrollmentKey != "" {
		secret, err := EnrollmentKeyInput(selection.EnrollmentKey, input)
		if err != nil {
			return err
		}
		native, identity, err = publisheridentity.EnrollNative(ctx, profile, control, authority, secret)
		if err != nil {
			if flags.Enrolled && (errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrNotFound)) {
				return failure.Wrap("enroll publication", failure.PublisherEnrollmentRequired, err)
			}
			return err
		}
	} else if selection.PublisherIdentityID != "" {
		native, identity, err = publisheridentity.LoadNative(ctx, profile, control, authority, selection.PublisherIdentityID)
		if err != nil {
			return err
		}
	} else {
		file, err := credentialfile.Read(selection.PublisherCredentialFile)
		if err != nil {
			return err
		}
		identity, _, err = file.Validate()
		if err != nil {
			return err
		}
		native, err = publisheridentity.LoadFile(selection.PublisherCredentialFile, server, control, authority)
		if err != nil {
			return err
		}
	}
	if flags.Enrolled && identity.Kind != authorityv1.SavedPublicUrl {
		return publisheridentity.ErrScope
	}
	if identity.Kind == authorityv1.Service {
		if flags.Service != "" && config.IsPublicService(project.Config.Services[flags.Service]) {
			return failure.Wrap("select enrolled service", failure.PublisherGrantMismatch, errors.New("grant is private"))
		}
		service, err := native.SavedService(ctx)
		if err != nil {
			return err
		}
		if flags.Protocol != "" && flags.Protocol != string(service.Protocol) {
			return failure.Wrap("select enrolled protocol", failure.PublisherGrantMismatch, errors.New("protocol differs from service"))
		}
		if output.Delegated != nil {
			output.Delegated()
		}
		private := ServiceOptions{PublicOptions: flags.PublicOptions, Protocol: string(service.Protocol), ConfiguredPrivate: true, TargetTLS: flags.TargetTLS, PublisherCredentialFile: selection.PublisherCredentialFile, PublisherIdentityID: identity.ClientId, EnrollmentInput: input}
		private.ServerURL = server
		if private.PublisherCredentialFile != "" {
			private.PublisherIdentityID = ""
		}
		if flags.SelectPrivate != nil {
			private.Limits, err = flags.SelectPrivate(service.Protocol)
			if err != nil {
				return err
			}
		}
		return PublishPrivate(ctx, private, flags.ServicePresentation)
	}
	// a saved-URL grant returns its exact URL; namespace grants allocate one
	// HTTP URL per invocation and remove that same allocation after drain.
	publicURL, err := native.SavedPublicURL(ctx)
	if errors.Is(err, publisheridentity.ErrScope) {
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
		publicURL, err = native.Allocate(ctx, b)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := native.DeletePublicURL(cleanup, publicURL.Id); err != nil && !errors.Is(err, clientcontrol.ErrNotFound) {
				result = errors.Join(result, err)
			}
		}()
	} else if err != nil {
		return err
	} else if flags.Ephemeral || flags.Anonymous || flags.Access != nil || len(flags.IP) > 0 {
		return failure.Wrap("select saved URL policy", failure.PublisherSavedPolicy, errors.New("saved policy overrides supplied"))
	}
	if publicURL.Purpose != controlv1.App || !publicURL.ServiceProtocol.Valid() {
		return failure.Wrap("read enrolled public URL", failure.ServerResponseInvalid, errors.New("control returned an unsupported saved URL"))
	}
	if flags.Protocol != "" && flags.Protocol != string(publicURL.ServiceProtocol) {
		return failure.Wrap("select enrolled protocol", failure.PublisherGrantMismatch, errors.New("protocol differs from public URL"))
	}
	if flags.SelectProtocol != nil {
		flags.Limits, err = flags.SelectProtocol(publicURL.ServiceProtocol)
		if err != nil {
			return err
		}
	}
	target, err := targetplan.EnrolledAddress(publicURL, flags.Target)
	if err != nil {
		return err
	}
	if flags.Enrolled && publicURL.Ephemeral {
		return publisheridentity.ErrScope
	}
	if flags.Enrolled {
		if err := profile.SelectPublisherIdentity(ctx, "job", RetainedScope(flags.Target), identity.ClientId); err != nil {
			return err
		}
	}
	options, err := publisherproxy.TargetOptionsForCA(flags.TargetCAFile, flags.ProjectRoot)
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
	tunnel, err := database.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Target: target, ServiceProtocol: publicURL.ServiceProtocol, Project: flags.ProjectRoot, Service: flags.Service})
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
	if publicURL.ServiceProtocol == controlv1.Http {
		if err := publisherproxy.PreflightWithOptions(ctx, target, options); err != nil {
			return err
		}
		output.configureBrowser(false)
	}
	membership := ""
	if publicURL.MembershipId != nil {
		membership = *publicURL.MembershipId
	}
	prefixes := []string{}
	if publicURL.AllowedIpPrefixes != nil {
		prefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
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
	cfg := publisher.Config{Control: native, ControlURL: server, State: profile, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, MembershipID: membership, PolicyRevision: uint64(publicURL.PolicyRevision), PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, Hostname: publicURL.CanonicalHostname, Target: target, AllowedIPPrefixes: prefixes, ServiceProtocol: publicURL.ServiceProtocol, TargetTLSName: flags.TargetTLSName, TargetOptions: options, PreserveSavedPublicURLTarget: publicURL.Target == "", Limits: flags.Limits, InspectionMode: inspection.Mode(flags.InspectionMode), QUICConnector: muxsession.QUICConnector{TLSConfig: transportTLS}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: transportTLS}}
	if flags.Enrolled {
		discovery, err := control.Discovery(ctx)
		if err != nil {
			return err
		}
		cfg.BrowserLoginAvailable = discovery.BrowserLoginAvailable != nil && *discovery.BrowserLoginAvailable
	}
	cfg.PublisherIdentityID = native.PublisherIdentityID()
	if publicURL.Ephemeral {
		cfg.Ephemeral = true
		cfg.AssignedPublicURL = &publicURL
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
	if publicURL.ServiceProtocol != controlv1.Http && len(cfg.Mounts) > 0 {
		return failure.Wrap("select enrolled mounts", failure.PublisherGrantMismatch, errors.New("TCP publication has HTTP path mounts"))
	}
	cfg.Logf = output.Logf
	cfg.Observe = func(event publisher.Event) error { return output.publisherEvent(ctx, tunnel, server, event) }
	if flags.Enrolled {
		supervisor.VerifyPublicationReadiness(ctx, &cfg, flags.ReadinessPath)
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
