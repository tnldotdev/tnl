package setup

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
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// publicationInstallation is the entire privilege boundary. it cannot carry an
// operator session, enrollment secret, arbitrary executable, or supervisor unit.
type Installation struct {
	Job        supervisor.Job      `json:"job"`
	Credential credentialfile.File `json:"credential"`
}

type RegistrationResult struct {
	Output string         `json:"output,omitempty"`
	Reason failure.Reason `json:"reason,omitempty"`
}

func (Installation) String() string   { return "private publication installation" }
func (Installation) GoString() string { return "private publication installation" }

type Publication struct {
	Database     *clientstate.Database
	Server       string
	Route        controlv1.PublicURL
	Control      publisheridentity.OwnerControl
	Options      supervisor.ServiceOptions
	Job          supervisor.Job
	TargetCAFile string
	ServerCAFile string
	ProjectRoot  string
}

type Presentation struct {
	Input       io.Reader
	Output      io.Writer
	Diagnostics io.Writer
	Installing  func() error
	Jobs        func([]supervisor.Job, string) error
}

func InstallPublication(ctx context.Context, selected Publication, presentation Presentation) error {
	options, database, server, publicURL := selected.Options, selected.Database, selected.Server, selected.Route
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
	control, authority, err := supervisor.Clients(supervisor.Job{Server: server})
	if err != nil {
		return err
	}
	credential, err := EnsurePublication(ctx, profile, selected.Control, control, authority, server, publicURL)
	if err != nil {
		return err
	}
	job := selected.Job
	job.ID, job.Server, job.PublicURLID, job.Protocol = supervisor.PublicURLJobKey(server, publicURL.Id), server, publicURL.Id, config.ProtocolHTTP
	job.PublisherIdentityID, job.GrantID, job.VerifyReadiness = credential.PublisherIdentityID, credential.GrantID, true
	caPath := selected.TargetCAFile
	if caPath != "" && !filepath.IsAbs(caPath) {
		caPath = filepath.Join(selected.ProjectRoot, caPath)
	}
	job.TargetCAPEM, err = ReadTrust(caPath)
	if err != nil {
		return err
	}
	job.ServerCAPEM, err = ReadTrust(selected.ServerCAFile)
	if err != nil {
		return err
	}
	return DeliverInstallation(ctx, options, Installation{Job: job, Credential: credential}, presentation)
}

func DeliverInstallation(ctx context.Context, options supervisor.ServiceOptions, payload Installation, presentation Presentation) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if options.User || os.Geteuid() == 0 {
		options.BinarySource = binary
		return Register(ctx, options, payload, supervisor.HostExecutor{}, presentation.Jobs)
	}
	// sudo reads the password from the terminal before the private payload pipe
	// is attached. no publisher key or human token enters argv or the environment.
	if err := presentation.Installing(); err != nil {
		return err
	}
	authorize := exec.CommandContext(ctx, "/usr/bin/sudo", "-v")
	authorize.Stdin, authorize.Stdout, authorize.Stderr = presentation.Input, presentation.Diagnostics, presentation.Diagnostics
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
	var result RegistrationResult
	if json.Unmarshal(response.Bytes(), &result) != nil {
		return failure.Wrap("read system installation result", failure.ServerResponseInvalid, supervisor.ErrScope)
	}
	if result.Reason != "" {
		if _, ok := failure.DefinitionFor(result.Reason); !ok {
			return supervisor.ErrScope
		}
		return failure.Wrap("install system publication", result.Reason, errors.New("privileged installation failed"))
	}
	_, err = io.WriteString(presentation.Output, result.Output)
	return err
}

func RegisterInput(ctx context.Context, resolveOptions func() (supervisor.ServiceOptions, error), input io.Reader, executor supervisor.Executor, render func([]supervisor.Job, string) error) error {
	data, err := io.ReadAll(io.LimitReader(input, (512<<10)+1))
	if err != nil || len(data) > 512<<10 {
		return supervisor.ErrScope
	}
	var payload Installation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF {
		return supervisor.ErrScope
	}
	options, err := resolveOptions()
	if err != nil {
		return err
	}
	options.BinarySource, err = os.Executable()
	if err != nil {
		return err
	}
	if executor == nil {
		executor = supervisor.HostExecutor{}
	}
	return Register(ctx, options, payload, executor, render)
}

func Register(ctx context.Context, options supervisor.ServiceOptions, payload Installation, executor supervisor.Executor, render func([]supervisor.Job, string) error) error {
	identity, private, err := payload.Credential.Validate()
	if err != nil {
		return err
	}
	job := payload.Job
	if payload.Credential.ControlURL != job.Server || job.PublisherIdentityID != identity.ClientId || job.GrantID != identity.GrantId {
		return supervisor.ErrScope
	}
	control, authority, err := supervisor.Clients(job)
	if err != nil {
		return err
	}
	native, err := publisheridentity.NewNative(control, authority, identity, private)
	if err != nil {
		return err
	}
	switch job.Kind {
	case supervisor.KindPublicURL:
		job.VerifyReadiness = true
		if identity.PublicUrlId == nil || *identity.PublicUrlId != job.PublicURLID || job.ID != supervisor.PublicURLJobKey(job.Server, job.PublicURLID) {
			return supervisor.ErrScope
		}
		publicURL, err := native.SavedPublicURL(ctx)
		if err != nil {
			return err
		}
		if publicURL.Id != job.PublicURLID || publicURL.Ephemeral || publicURL.Purpose != controlv1.App || publicURL.ServiceProtocol != controlv1.Http {
			return supervisor.ErrScope
		}
		if _, err := target.EnrolledAddress(publicURL, job.Target); err != nil {
			return err
		}
	case supervisor.KindService:
		if identity.ServiceId == nil || *identity.ServiceId != job.ServiceID || job.ID != supervisor.ServiceJobKey(job.Server, job.ServiceID) {
			return supervisor.ErrScope
		}
		service, err := native.SavedService(ctx)
		if err != nil {
			return err
		}
		if service.TrustRevision != job.TrustRevision || service.PublisherPool != job.PublisherPool {
			return supervisor.ErrScope
		}
		if err := publisheridentity.MatchServiceDeclaration(service, string(job.Protocol), job.Trust); err != nil {
			return err
		}
		if err := target.PreflightPrivate(ctx, job.TargetPlan()); err != nil {
			return err
		}
	default:
		return supervisor.ErrScope
	}
	registry, err := supervisor.Open(ctx, supervisor.OpenOptions{Root: options.Root, User: options.User, TestOwnerUID: options.TestOwnerUID})
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := registry.Install(ctx, job, identity, private); err != nil {
		return err
	}
	// desired state and the scoped key are durable before the supervisor starts.
	// a failed install is retried with this same identity, never a broader grant.
	if err := supervisor.InstallService(ctx, options, executor); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := WaitReady(waitCtx, registry, job.ID); err != nil {
		return err
	}
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	return render(jobs, job.ID)
}

func WaitReady(ctx context.Context, registry *supervisor.Registry, id string) error {
	for {
		job, err := registry.ResolveJob(ctx, id)
		if err != nil {
			return err
		}
		if job.Enabled && job.Status.State == "ready" && (job.Kind == supervisor.KindService || job.Status.RunNumber != 0 && job.Status.PublicURL != "") {
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
