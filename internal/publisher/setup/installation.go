package publisherprovision

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

	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// publicationInstallation is the entire privilege boundary. it cannot carry an
// operator session, enrollment secret, arbitrary executable, or supervisor unit.
type Installation struct {
	Job        publisherjob.Job    `json:"job"`
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
	Control      nativeauth.OwnerControl
	Options      publisherjob.ServiceOptions
	Job          publisherjob.Job
	TargetCAFile string
	ServerCAFile string
	ProjectRoot  string
}

type Presentation struct {
	Input       io.Reader
	Output      io.Writer
	Diagnostics io.Writer
	Installing  func() error
	Jobs        func([]publisherjob.Job, string) error
}

func InstallPublication(ctx context.Context, selected Publication, presentation Presentation) error {
	options, database, server, route := selected.Options, selected.Database, selected.Server, selected.Route
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
	credential, err := EnsurePublication(ctx, profile, selected.Control, control, authority, server, route)
	if err != nil {
		return err
	}
	job := selected.Job
	job.ID, job.Server, job.PublicURLID, job.Protocol = publisherjob.PublicURLJobKey(server, route.Id), server, route.Id, config.ProtocolHTTP
	job.PublisherID, job.GrantID, job.VerifyReadiness = credential.PublisherID, credential.GrantID, true
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

func DeliverInstallation(ctx context.Context, options publisherjob.ServiceOptions, payload Installation, presentation Presentation) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if options.User || os.Geteuid() == 0 {
		options.BinarySource = binary
		return Register(ctx, options, payload, publisherjob.HostExecutor{}, presentation.Jobs)
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
		return failure.Wrap("read system installation result", failure.ServerResponseInvalid, publisherjob.ErrScope)
	}
	if result.Reason != "" {
		if _, ok := failure.DefinitionFor(result.Reason); !ok {
			return publisherjob.ErrScope
		}
		return failure.Wrap("install system publication", result.Reason, errors.New("privileged installation failed"))
	}
	_, err = io.WriteString(presentation.Output, result.Output)
	return err
}

func RegisterInput(ctx context.Context, resolveOptions func() (publisherjob.ServiceOptions, error), input io.Reader, executor publisherjob.Executor, render func([]publisherjob.Job, string) error) error {
	data, err := io.ReadAll(io.LimitReader(input, (512<<10)+1))
	if err != nil || len(data) > 512<<10 {
		return publisherjob.ErrScope
	}
	var payload Installation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF {
		return publisherjob.ErrScope
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
		executor = publisherjob.HostExecutor{}
	}
	return Register(ctx, options, payload, executor, render)
}

func Register(ctx context.Context, options publisherjob.ServiceOptions, payload Installation, executor publisherjob.Executor, render func([]publisherjob.Job, string) error) error {
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
		if _, err := target.EnrolledAddress(route, job.Target); err != nil {
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
		if err := target.PreflightPrivate(ctx, job.PrivateTargetPlan()); err != nil {
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
	if err := WaitReady(waitCtx, registry, job.ID); err != nil {
		return err
	}
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	return render(jobs, job.ID)
}

func WaitReady(ctx context.Context, registry *publisherjob.Registry, id string) error {
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
