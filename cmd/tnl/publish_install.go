package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/internal/publisherprovision"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// publicationInstallation is the entire privilege boundary. it cannot carry an
// operator session, enrollment secret, arbitrary executable, or supervisor unit.
type publicationInstallation struct {
	Job        publisherjob.Job    `json:"job"`
	Credential credentialfile.File `json:"credential"`
}

type publicationRegistrationResult struct {
	Output string         `json:"output,omitempty"`
	Reason failure.Reason `json:"reason,omitempty"`
}

func (publicationInstallation) String() string   { return "private publication installation" }
func (publicationInstallation) GoString() string { return "private publication installation" }

func runPublicationInstall(ctx context.Context, flags publishCommand, output, diagnostics io.Writer) error {
	if flags.Service != "" {
		effective, err := flags.project.EffectiveService(flags.Service)
		if err != nil {
			return err
		}
		applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel)
		applyBuiltInHostname(&flags.tunnelFlags, flags.Service, flags.project.Worktree)
		if flags.Team == "" {
			flags.selectedTeam, err = projectTeamForServer(flags.ServerURL, effective.Server, effective.Team)
			if err != nil {
				return err
			}
		}
	}
	if flags.Name == "" && flags.PublicURL == "" || flags.Demo || flags.Ephemeral || flags.Open || flags.Protocol != "" && flags.Protocol != "http" {
		return publisherCLIError("install a saved HTTP public URL with --name or --public-url and a stable target")
	}
	if flags.inspectionModeFromCLI && flags.InspectionMode != config.InspectionNone {
		return publisherCLIError("installed publications support --inspection-mode=none")
	}
	if err := validateTCPPublishOptions(flags, controlv1.Http); err != nil {
		return err
	}
	options, err := (systemStateFlags{System: flags.System, SystemStateDir: flags.SystemStateDir}).options()
	if err != nil {
		return err
	}
	if _, err := publisherjob.ServiceUnit(runtime.GOOS, "/tnl", options.Root); err != nil {
		return err
	}
	target, err := normalizePublishTarget(flags.Target, controlv1.Http)
	if err != nil {
		return err
	}
	targetOptions, err := targetOptionsForCA(flags.TargetCAFile, flags.projectRoot)
	if err != nil {
		return err
	}
	targetOptions.ServerName = flags.TargetTLSName
	if err := localproxy.PreflightWithOptions(ctx, target, targetOptions); err != nil {
		return err
	}
	server, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer database.Close()
	// setup uses the existing interactive login. its state is never handed to
	// the supervisor, including when sudo changes HOME.
	authenticated, err := authenticatePublisher(ctx, database, server, flags.AccessToken, "tnl publish", os.Stdin, diagnostics)
	if err != nil {
		return err
	}
	team := flags.selectedTeam
	if team == "" {
		team = flags.Team
	}
	services, err := preparePublisherServices(ctx, database, server, flags.PublicURL, flags.Name, flags.Domain, team, false, authenticated)
	if err != nil {
		return err
	}
	policy, err := resolveVisitorAccess(ctx, authenticated.Control, flags.access, flags.Anonymous, flags.IP)
	if err != nil {
		return err
	}
	cfg := services.config(target, policy.prefixes, flags.limits())
	if policy.explicit {
		cfg.AccessMode = policy.access
	}
	route, err := reserveConfiguredURL(ctx, services, cfg)
	if err != nil {
		return err
	}
	// one protected setup journal per supervisor root. EnsurePublication retains
	// the exact key through failed registration, lost replies, and retries.
	digest := sha256.Sum256([]byte(options.Root))
	staging := filepath.Join(database.Root(), "publisher-install-"+hex.EncodeToString(digest[:12]))
	setup, err := clientstate.OpenWithOptions(ctx, staging, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return err
	}
	defer setup.Close()
	profile, err := setup.Server(ctx, server)
	if err != nil {
		return err
	}
	control, authority, err := publisherjob.Clients(publisherjob.Job{Server: server})
	if err != nil {
		return err
	}
	credential, err := publisherprovision.EnsurePublication(ctx, profile, authenticated.Control, control, authority, server, route)
	if err != nil {
		return err
	}
	job := publisherjob.Job{ID: publisherjob.PublicURLJobKey(server, route.Id), Name: flags.ServiceName, Server: server, Target: target,
		PublisherID: credential.PublisherID, GrantID: credential.GrantID, PublicURLID: route.Id, Protocol: config.ProtocolHTTP,
		TargetTLSName: flags.TargetTLSName, Limits: flags.limits(), VerifyReadiness: true, ReadinessPath: flags.publicationReadinessPath()}
	if job.Name == "" {
		job.Name = flags.Name
	}
	caPath := flags.TargetCAFile
	if caPath != "" && !filepath.IsAbs(caPath) {
		caPath = filepath.Join(flags.projectRoot, caPath)
	}
	job.TargetCAPEM, err = systemTrustInput(caPath)
	if err != nil {
		return err
	}
	job.ServerCAPEM, err = systemTrustInput(flags.ServerCAFile)
	if err != nil {
		return err
	}
	return deliverPublicationInstallation(ctx, options, publicationInstallation{Job: job, Credential: credential}, output, diagnostics)
}

func deliverPublicationInstallation(ctx context.Context, options publisherjob.ServiceOptions, payload publicationInstallation, output, diagnostics io.Writer) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if options.User || os.Geteuid() == 0 {
		options.BinarySource = binary
		return registerPublication(ctx, options, payload, output, publisherjob.HostExecutor{})
	}
	// sudo reads the password from the terminal before the private payload pipe
	// is attached. no publisher key or human token enters argv or the environment.
	if err := writeHumanFrame(diagnostics, "tnl publish", "installing", "sudo will ask for permission to install the system publisher"); err != nil {
		return err
	}
	authorize := exec.CommandContext(ctx, "/usr/bin/sudo", "-v")
	authorize.Stdin, authorize.Stdout, authorize.Stderr = os.Stdin, diagnostics, diagnostics
	if err := authorize.Run(); err != nil {
		return failure.Wrap("authorize system installation", failure.ClientStateUnavailable, err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "--", binary, "--no-telemetry", "service", "register", "--system", "--system-state-dir", options.Root, "--private-result")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	var response bytes.Buffer
	command.Stdin, command.Stdout = bytes.NewReader(data), &response
	// the parent owns error rendering. child diagnostics never cross this boundary.
	if err := command.Run(); err != nil {
		return failure.Wrap("install system publication", failure.ClientStateUnavailable, err)
	}
	var result publicationRegistrationResult
	if json.Unmarshal(response.Bytes(), &result) != nil {
		return failure.Wrap("read system installation result", failure.ServerResponseInvalid, publisherjob.ErrScope)
	}
	if result.Reason != "" {
		if _, ok := failure.DefinitionFor(result.Reason); !ok {
			return publisherjob.ErrScope
		}
		return failure.Wrap("install system publication", result.Reason, errors.New("privileged installation failed"))
	}
	_, err = io.WriteString(output, result.Output)
	return err
}

func runPublicationRegister(ctx context.Context, flags serviceRegisterCommand, input io.Reader, output io.Writer, executor publisherjob.Executor) error {
	if flags.PrivateResult {
		flags.PrivateResult = false
		var buffer bytes.Buffer
		result := publicationRegistrationResult{}
		err := runPublicationRegister(ctx, flags, input, &buffer, executor)
		if err == nil {
			result.Output = buffer.String()
		} else if classified, ok := failure.Of(err); ok {
			result.Reason = classified.Reason()
		} else {
			result.Reason = failure.ClientStateUnavailable
		}
		return json.NewEncoder(output).Encode(result)
	}
	data, err := io.ReadAll(io.LimitReader(input, (512<<10)+1))
	if err != nil || len(data) > 512<<10 {
		return publisherjob.ErrScope
	}
	var payload publicationInstallation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF {
		return publisherjob.ErrScope
	}
	options, err := flags.options()
	if err != nil {
		return err
	}
	options.BinarySource, err = os.Executable()
	if err != nil {
		return err
	}
	if executor == nil {
		executor = publisherjob.HostExecutor{}
	}
	return registerPublication(ctx, options, payload, output, executor)
}

func registerPublication(ctx context.Context, options publisherjob.ServiceOptions, payload publicationInstallation, output io.Writer, executor publisherjob.Executor) error {
	identity, private, err := payload.Credential.Validate()
	if err != nil {
		return err
	}
	job := payload.Job
	if payload.Credential.ControlURL != job.Server || job.PublisherID != identity.ClientId || job.GrantID != identity.GrantId {
		return publisherjob.ErrScope
	}
	control, authority, err := publisherjob.Clients(job)
	if err != nil {
		return err
	}
	native, err := nativeauth.NewNative(control, authority, identity, private)
	if err != nil {
		return err
	}
	switch job.Kind {
	case publisherjob.KindPublicURL:
		job.VerifyReadiness = true
		if identity.PublicUrlId == nil || *identity.PublicUrlId != job.PublicURLID || job.ID != publisherjob.PublicURLJobKey(job.Server, job.PublicURLID) {
			return publisherjob.ErrScope
		}
		route, err := native.SavedURL(ctx)
		if err != nil {
			return err
		}
		if route.Id != job.PublicURLID || route.Ephemeral || route.Purpose != controlv1.App || route.ServiceProtocol != controlv1.Http {
			return publisherjob.ErrScope
		}
		if _, err := enrolledTarget(route, job.Target); err != nil {
			return err
		}
	case publisherjob.KindPrivateService:
		if identity.PrivateServiceId == nil || *identity.PrivateServiceId != job.PrivateServiceID || job.ID != publisherjob.PrivateServiceJobKey(job.Server, job.PrivateServiceID) {
			return publisherjob.ErrScope
		}
		service, err := native.SavedPrivateService(ctx)
		if err != nil {
			return err
		}
		if service.TrustRevision != job.TrustRevision || service.PublisherPool != job.PublisherPool {
			return publisherjob.ErrScope
		}
		if err := nativeauth.MatchPrivateServiceDeclaration(service, string(job.Protocol), job.Trust); err != nil {
			return err
		}
		if err := publisherjob.PreflightPrivate(ctx, job); err != nil {
			return err
		}
	default:
		return publisherjob.ErrScope
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User, TestOwnerUID: options.TestOwnerUID})
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := registry.Install(ctx, job, identity, private); err != nil {
		return err
	}
	// desired state and the scoped key are durable before the supervisor starts.
	// a failed install is retried with this same identity, never a broader grant.
	if err := publisherjob.InstallService(ctx, options, executor); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := waitInstalledPublicationReady(waitCtx, registry, job.ID); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl publish", job.ID)
}

func waitInstalledPublicationReady(ctx context.Context, registry *publisherjob.Registry, id string) error {
	for {
		job, err := registry.ResolveJob(ctx, id)
		if err != nil {
			return err
		}
		if job.Enabled && job.Status.State == "ready" && (job.Kind == publisherjob.KindPrivateService || job.Status.PublishRunNumber != 0 && job.Status.PublicURL != "") {
			return nil
		}
		if job.Status.State == "blocked" {
			return failure.Wrap("start installed publication", failure.TunnelUnavailable, errors.New("installed publisher is blocked"))
		}
		select {
		case <-ctx.Done():
			return failure.Wrap("verify installed publication", failure.AppReadinessTimeout, context.Cause(ctx))
		case <-time.After(100 * time.Millisecond):
		}
	}
}
