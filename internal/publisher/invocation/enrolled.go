package invocation

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisheradhoc "github.com/tnldotdev/tnl/internal/publisher/adhoc"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
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

// PublishEnrolled resolves one scoped identity and composes the service run with
// its caller-owned journal, inspection, process coordination, and exact cleanup.
func PublishEnrolled(ctx context.Context, flags EnrolledOptions, selection EnrolledSelection, output *Presentation, input io.Reader) (result error) {
	selected := 0
	for _, value := range []string{selection.EnrollmentKey, selection.PublisherIdentityID, selection.PublisherCredentialFile} {
		if value != "" {
			selected++
		}
	}
	if selected != 1 || flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo {
		return failure.Wrap("select scoped publisher", failure.PublisherSelectionInvalid, errors.New("conflicting selection"))
	}
	var file credentialfile.File
	if selection.PublisherCredentialFile != "" {
		var err error
		file, err = credentialfile.Read(selection.PublisherCredentialFile)
		if err != nil {
			return err
		}
		if flags.ServerURL != "" {
			server, err := naming.CanonicalControlURL(flags.ServerURL)
			if err != nil || server != file.ControlURL {
				return publisheridentity.ErrScope
			}
		}
		flags.ServerURL = file.ControlURL
	}
	server, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer database.Close()
	var prepared *publisheradhoc.Prepared
	var tunnel *clientstate.Tunnel
	var recorder *clientstate.InspectionRecorder
	var stopRuntime func() error
	// install ownership before preparation. runs return only after joining;
	// process stop and allocation cleanup finish before borrowed state closes.
	defer func() {
		if stopRuntime != nil {
			result = errors.Join(result, stopRuntime())
		}
		if prepared != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			result = errors.Join(result, prepared.Cleanup(cleanup))
			cancel()
		}
		if recorder != nil {
			recorder.Close()
		}
		if tunnel != nil {
			finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			result = errors.Join(result, tunnel.Finish(finish, result))
			cancel()
		}
	}()
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
	capabilities := publisheridentity.NativeControl{Services: control, Allocations: control, Runtime: control}
	if selection.EnrollmentKey != "" {
		secret, err := EnrollmentKeyInput(selection.EnrollmentKey, input)
		if err != nil {
			return err
		}
		native, identity, err = publisheridentity.EnrollNative(ctx, profile, capabilities, authority, secret)
		if err != nil {
			if flags.Enrolled && (errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrNotFound)) {
				return failure.Wrap("enroll publication", failure.PublisherEnrollmentRequired, err)
			}
			return err
		}
	} else if selection.PublisherIdentityID != "" {
		native, identity, err = publisheridentity.LoadNative(ctx, profile, capabilities, authority, selection.PublisherIdentityID)
		if err != nil {
			return err
		}
	} else {
		var key []byte
		identity, key, err = file.Validate()
		if err != nil {
			return err
		}
		native, err = publisheridentity.NewNative(capabilities, authority, identity, key)
		if err != nil {
			return err
		}
	}
	if flags.Enrolled && identity.Kind != authorityv1.Service {
		return publisheridentity.ErrScope
	}
	var saved controlv1.Service
	var cfg publisherservice.RunConfig
	var plan targetplan.TargetPlan
	run := publisherservice.Publish
	if identity.Kind == authorityv1.Service {
		saved, err = native.SavedService(ctx)
		if err != nil {
			return err
		}
		if flags.SelectProtocol != nil {
			flags.Limits, err = flags.SelectProtocol(saved.Protocol)
			if err != nil {
				return err
			}
		}
		plan, err = enrolledServicePlan(ctx, flags, saved)
		if err != nil {
			return err
		}
		if flags.Service != "" && flags.Traffic == nil {
			effective, err := flags.Project.EffectiveService(flags.Service)
			if err != nil {
				return err
			}
			flags.Traffic, err = config.ResolveTrafficSelection(effective.Traffic)
			if err != nil {
				return err
			}
		}
		native, err = native.WithTraffic(flags.Traffic)
		if err != nil {
			return err
		}
		cfg = publisherservice.RunConfig{Control: native, State: profile, Access: native.Access,
			PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
			ServiceID: saved.Id, Target: plan.Target, Metadata: publisheridentity.ServiceMetadata(saved)}
		if saved.Protocol != controlv1.ServiceProtocolHTTP {
			cfg.StreamCapacity = int32(flags.Limits.Concurrency)
		}
		run = func(ctx context.Context, cfg publisherservice.RunConfig) error {
			return targetplan.PublishPrivate(ctx, plan, cfg, targetplan.TargetHooks{Resolver: flags.Resolver})
		}
		flags.Target = plan.Target
		if flags.ServicePresentation != nil {
			if output != nil && output.Delegated != nil {
				output.Delegated()
			}
			output = servicePresentation(flags.ServicePresentation, saved, flags.Target)
		}
	} else if identity.Kind == authorityv1.Namespace {
		if flags.Protocol != "" && flags.Protocol != "http" || flags.TargetTLSName != "" {
			return failure.Wrap("select namespace target", failure.PublisherNamespaceOptions, errors.New("unsupported namespace options"))
		}
		if flags.SelectProtocol != nil {
			flags.Limits, err = flags.SelectProtocol(controlv1.ServiceProtocolHTTP)
			if err != nil {
				return err
			}
		}
		target, err := targetsyntax.NormalizeTarget(flags.Target)
		if err != nil {
			return err
		}
		if flags.TargetTLS != nil && !*flags.TargetTLS && (strings.HasPrefix(target, "https://") || flags.TargetCAFile != "") {
			return failure.Wrap("select namespace target", failure.PublisherNamespaceOptions, errors.New("target TLS is disabled while target trust is configured"))
		}
		targetFlags := ServiceOptions{PublicOptions: flags.PublicOptions, TargetTLS: flags.TargetTLS}
		if strings.HasPrefix(target, "https://") && targetFlags.TargetTLS == nil {
			targetFlags.TargetTLS = new(true)
		}
		trust, err := CaptureServiceTargetTrust(ctx, targetFlags, controlv1.ServiceProtocolHTTP, target)
		if err != nil {
			return err
		}
		plan = targetplan.TargetPlan{Protocol: config.ProtocolHTTP, Target: target, Trust: trust}
		if err := targetplan.PreflightPrivate(ctx, plan); err != nil {
			return err
		}
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			return err
		}
		policy, err := resolveVisitorAccess(ctx, control, flags.Access, flags.Anonymous, flags.IP)
		if err != nil {
			return err
		}
		options := publisheradhoc.Options{ControlURL: server, State: profile, InvocationID: invocation, Target: target, Limits: flags.Limits,
			AccessMode: policy.access, IP: policy.prefixes}
		if flags.RequirePostQuantum != nil {
			options.RequirePostQuantum = *flags.RequirePostQuantum
		}
		if trust != nil {
			declaration, err := trust.Declaration()
			if err != nil {
				return err
			}
			options.TargetTLS = &controlv1.ProjectTargetTLS{Hostname: declaration.Hostname, Digest: declaration.Digest}
			if len(declaration.CAPEM) != 0 {
				options.TargetTLS.CaPem = new(string(declaration.CAPEM))
			}
		}
		options.Publisher, err = native.WithTraffic(flags.Traffic)
		if err != nil {
			return err
		}
		prepared, err = publisheradhoc.Prepare(ctx, options)
		if err != nil {
			return err
		}
		saved, cfg, native = prepared.Service, prepared.Config, prepared.Publisher()
		flags.Target = target
	} else {
		return publisheridentity.ErrScope
	}
	if saved.ExpiresAt != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *saved.ExpiresAt)
		defer cancel()
	}
	if flags.Enrolled {
		if err := profile.SelectPublisherIdentity(ctx, "job", RetainedScope(flags.Target), identity.ClientId); err != nil {
			return err
		}
	}
	if flags.ProjectRoot == "" {
		flags.ProjectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	tunnel, err = database.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Target: flags.Target,
		ServiceID: saved.Id, ServiceProtocol: saved.Protocol, Project: flags.ProjectRoot, Service: flags.Service})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	if err := output.starting(tunnel.ID(), flags.Target); err != nil {
		return err
	}
	if saved.Protocol == controlv1.ServiceProtocolHTTP && saved.Endpoint.Public {
		output.configureBrowser(false)
	}
	settings := flags.Inspection
	if flags.InspectionMode != "" {
		settings = config.MergeInspection(settings, &config.Inspection{Mode: &flags.InspectionMode})
	}
	policy, err := config.ResolveInspection(settings, string(saved.Protocol))
	if err != nil {
		return err
	}
	cfg.Telemetry = flags.Telemetry
	if flags.TelemetryDisabled {
		cfg.Telemetry = nil
	}
	cfg.TransportTLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.InspectionMode = policy.Mode
	cfg.PreferredRegions = slices.Clone(flags.PreferredRegions)
	cfg.ProjectRoot, cfg.ProjectService = flags.ProjectRoot, flags.Service
	recorder, err = NewInspectionRecorder(ctx, tunnel, flags.ProjectRoot, flags.Service, config.InspectionMode(policy.Mode), flags.Inspection)
	if err != nil {
		return err
	}
	cfg.ObserveSummary = SummaryObservation(recorder)
	cfg.Mounts, err = ProjectMounts(ctx, flags.Project, flags.Service, nil, flags.Resolver)
	if err != nil {
		return err
	}
	if saved.Protocol != controlv1.ServiceProtocolHTTP && len(cfg.Mounts) > 0 {
		return failure.Wrap("select enrolled mounts", failure.PublisherGrantMismatch, errors.New("TCP publication has HTTP path mounts"))
	}
	if flags.Enrolled && saved.Protocol == controlv1.ServiceProtocolHTTP && saved.Endpoint.Public {
		path := flags.ReadinessPath
		if path == "" {
			path = "/"
		}
		publish := run
		run = func(ctx context.Context, cfg publisherservice.RunConfig) error {
			var current httpaccess.ReadinessRun
			var proof *httpaccess.ReadinessProof
			cfg.ReadinessProof = func(run httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
				current = run
				proof, _ = httpaccess.NewReadinessProof(run, path)
				return proof
			}
			ready := cfg.Ready
			cfg.Ready = func() error {
				if current.Subject != (visitorscope.Scope{Kind: visitorscope.Service, ID: saved.Id}) {
					return publisheridentity.ErrScope
				}
				if err := installedjobs.VerifyServiceReadiness(ctx, current, path, proof); err != nil {
					return err
				}
				return ready()
			}
			return publish(ctx, cfg)
		}
	}
	stopRuntime, err = startDeployedPublisher(ctx, native, server)
	if err != nil {
		return err
	}
	return RunServiceCLI(ctx, tunnel, saved, cfg, output, run)
}

func enrolledServicePlan(ctx context.Context, flags EnrolledOptions, saved controlv1.Service) (targetplan.TargetPlan, error) {
	var plan targetplan.TargetPlan
	if err := validateProfileService(saved); err != nil {
		return plan, err
	}
	if saved.Ephemeral {
		return plan, publisheridentity.ErrScope
	}
	if flags.Protocol != "" && flags.Protocol != string(saved.Protocol) {
		return plan, failure.Wrap("select enrolled protocol", failure.PublisherGrantMismatch, errors.New("protocol differs from service"))
	}
	if flags.Ephemeral || flags.Anonymous || flags.Access != nil || len(flags.IP) > 0 ||
		saved.Protocol == controlv1.ServiceProtocolHTTP && flags.Limits != (applicationlimits.Limits{}) {
		return plan, failure.Wrap("select saved service policy", failure.PublisherSavedPolicy, errors.New("saved policy overrides supplied"))
	}
	if saved.Protocol != controlv1.ServiceProtocolHTTP && (flags.Limits.Requests != 0 || flags.Limits.RateRequests != 0 ||
		flags.Limits.RatePer != 0 || flags.Limits.RateBurst != 0 || flags.Limits.Concurrency < 0 || flags.Limits.Concurrency > 4096 || flags.ReadinessPath != "") {
		return plan, failure.Wrap("select enrolled capabilities", failure.PublisherGrantMismatch, errors.New("HTTP limits and readiness require HTTP; stream capacity must be between 1 and 4096"))
	}
	if flags.RequirePostQuantum != nil && *flags.RequirePostQuantum != saved.RequirePostQuantum {
		return plan, failure.Wrap("select visitor TLS policy", failure.PublisherGrantMismatch, errors.New("saved service post-quantum requirement differs; update it with a manager sign-in"))
	}
	if flags.Service != "" {
		source := flags.Project.LocalPublicationIdentity()
		if saved.Source == nil || saved.Source.ProjectKey != source.Key || saved.Source.SourceFingerprint != source.Fingerprint ||
			saved.Source.Service != flags.Service || saved.Source.WorktreeKey != flags.Project.LocalWorktreeKey() {
			return plan, failure.Wrap("select local service publisher", failure.PublisherGrantMismatch, errors.New("grant differs from local publication identity"))
		}
		resolved, err := targetplan.ResolveTarget(ctx, flags.Project, flags.Service, flags.Resolver)
		if err != nil {
			return plan, err
		}
		if resolved.Target == nil {
			return plan, publisherCLIError("service target has not been discovered")
		}
		flags.Target = string(*resolved.Target)
		plan.Project, plan.ProjectService = &flags.Project, flags.Service
	}
	target, err := targetplan.NormalizePrivateAddress(flags.Target, saved.Protocol)
	if err != nil {
		return plan, err
	}
	trust, err := publisheridentity.ServiceTrust(saved)
	if err != nil {
		return plan, err
	}
	if flags.TargetTLS != nil && !*flags.TargetTLS && (flags.TargetTLSName != "" || flags.TargetCAFile != "" || strings.HasPrefix(target, "https://")) {
		return plan, failure.Wrap("select target TLS", failure.PublisherGrantMismatch, errors.New("target TLS is disabled while target trust is configured"))
	}
	if flags.Service != "" || flags.TargetTLS != nil || flags.TargetTLSName != "" || flags.TargetCAFile != "" {
		trust, err = CaptureServiceTargetTrust(ctx, ServiceOptions{PublicOptions: flags.PublicOptions, TargetTLS: flags.TargetTLS}, saved.Protocol, target)
		if err != nil {
			return plan, err
		}
	} else if saved.Protocol == controlv1.ServiceProtocolHTTP && trust != nil && !strings.Contains(flags.Target, "://") {
		target = "https://" + strings.TrimPrefix(target, "http://")
	}
	if err := publisheridentity.MatchServiceDeclaration(saved, string(saved.Protocol), trust); err != nil {
		return plan, failure.Wrap("match service declaration", failure.PublisherGrantMismatch, err)
	}
	plan.Protocol, plan.Target, plan.Trust = config.ProtocolName(saved.Protocol), target, trust
	if err := plan.Normalize(); err != nil {
		return plan, err
	}
	if err := targetplan.PreflightPrivate(ctx, plan); err != nil {
		return plan, err
	}
	return plan, nil
}
