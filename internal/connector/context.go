package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

type ContextOptions struct {
	Directory, Workload, Manifest, TeamID, StateDir string
	Service                                         []string
}

type OwnerStartOptions struct {
	ContextOptions
	RunnerTemp                                         string
	ParentPID                                          int
	KubeTokenFile, KubeUserConfig, KubeUser, Namespace string
}

type OwnerServeOptions struct {
	OwnerStartOptions
	OwnerDirectory string
}

func connectionProject(ctx context.Context, options ContextOptions) (projectConfiguration, connectorruntime.Context, error) {
	if options.Manifest != "" {
		return connectionManifest(options)
	}
	if options.TeamID != "" && !opaqueid.Valid(options.TeamID, opaqueid.TeamPrefix) {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	selection, err := clientproject.SelectProjectConfig(ctx, directory, "", os.Getenv("TNL_CONFIG"), false)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	// CI source/worktree scope does not depend on a local human state database.
	project, err := clientproject.Resolve(ctx, selection, directory, [32]byte{})
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	server := clientserver.DefaultURL
	if project.Config.Server != nil {
		server = *project.Config.Server
	}
	if selected := os.Getenv("TNL_SERVER"); selected != "" {
		server = selected
	} else if options.Workload == "" && project.Config.Server == nil {
		selected, database, err := clientserver.Open(ctx, options.StateDir, "")
		if err != nil {
			return projectConfiguration{}, connectorruntime.Context{}, err
		}
		server = selected
		if err := database.Close(); err != nil {
			return projectConfiguration{}, connectorruntime.Context{}, err
		}
	}
	server, err = clientstate.CanonicalServer(server)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	services := slices.Clone(options.Service)
	if options.Workload == "" && len(services) == 0 {
		for name, service := range project.Config.Services {
			if !isConnectPublicURL(service) {
				services = append(services, name)
			}
		}
	}
	if options.Workload != "" {
		policy, ok := project.Config.Workloads[options.Workload]
		if !ok {
			return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
		}
		if len(services) == 0 {
			services = slices.Clone(policy.Services)
		}
		for _, name := range services {
			if !slices.Contains(policy.Services, name) {
				return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
			}
		}
	}
	if len(services) == 0 {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
	}
	slices.Sort(services)
	for _, name := range services {
		if service, ok := project.Config.Services[name]; !ok || isConnectPublicURL(service) {
			return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
		}
		effective, err := project.EffectiveService(name)
		if err != nil {
			return projectConfiguration{}, connectorruntime.Context{}, err
		}
		if effective.Server != nil {
			selected, err := clientstate.CanonicalServer(*effective.Server)
			if err != nil || selected != server {
				return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
			}
		}
	}
	team := options.TeamID
	if team == "" && project.Config.Team != nil {
		team = *project.Config.Team
	}
	var appliedBinding *connectorruntime.Binding
	if binding, err := connectorruntime.ReadBinding(project.Root); err == nil && binding.Server == server && binding.ProjectKey == source.Key && binding.SourceID == source.Fingerprint {
		appliedBinding = &binding
	}
	if options.Workload != "" && !opaqueid.Valid(team, opaqueid.TeamPrefix) {
		if appliedBinding != nil && appliedBinding.Team == team {
			team = appliedBinding.TeamID
		}
		if team == "" {
			return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrTeam
		}
	}
	encoded, err := json.Marshal(struct {
		Config   config.TNL
		Server   string
		Source   clientproject.SourceIdentity
		Worktree string
		Binding  *connectorruntime.Binding
	}{project.Config, server, source, project.LocalWorktreeKey(), appliedBinding})
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	digest := sha256.Sum256(encoded)
	scope := connectorruntime.Context{Schema: 1, Directory: project.Root, ConfigDigest: hex.EncodeToString(digest[:]), Server: server, Audience: server, TeamID: team, ProjectKey: source.Key, SourceID: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), ProjectLabel: source.Label, Workload: options.Workload, Services: services}
	return projectConfiguration{Project: project}, scope, scope.Validate()
}

// deployed artifacts need neither Git nor a project config loader at runtime.
// the manifest selects a saved policy; only control grants service rights.
func connectionManifest(options ContextOptions) (projectConfiguration, connectorruntime.Context, error) {
	m, err := workloadmanifest.Read(options.Manifest)
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	w, ok := m.Workloads[options.Workload]
	if !ok || options.TeamID != "" && options.TeamID != m.Team {
		return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
	}
	directory, err := filepath.Abs(options.Directory)
	if err == nil {
		directory, err = filepath.EvalSymlinks(directory)
	}
	if err != nil {
		return projectConfiguration{}, connectorruntime.Context{}, err
	}
	services := slices.Clone(options.Service)
	if len(services) == 0 {
		services = slices.Clone(w.Services)
	}
	slices.Sort(services)
	for _, s := range services {
		if !slices.Contains(w.Services, s) {
			return projectConfiguration{}, connectorruntime.Context{}, connectorruntime.ErrInvalid
		}
	}
	b, _ := json.Marshal(m)
	digest := sha256.Sum256(b)
	configuration := config.TNL{Server: &m.Server, Team: &m.Team, Services: config.Services{}, Workloads: map[string]config.Workload{options.Workload: {Provider: w.Provider, Services: w.Services, MaxDuration: new(config.Duration(time.Duration(w.MaxDurationSeconds) * time.Second))}}}
	for _, s := range services {
		configuration.Services[s] = config.Service{Protocol: new(m.Services[s])}
	}
	scope := connectorruntime.Context{Schema: 1, Directory: directory, ConfigDigest: hex.EncodeToString(digest[:]), Server: m.Server, Audience: m.Server, TeamID: m.Team, ProjectKey: m.ProjectKey, SourceID: m.SourceFingerprint, WorktreeKey: "deployment", ProjectLabel: m.ProjectLabel, Workload: options.Workload, Services: services}
	return projectConfiguration{Project: clientproject.Project{Root: directory, Config: configuration}}, scope, scope.Validate()
}

func (o Operations) ServeOwner(ctx context.Context, options OwnerServeOptions, input io.Reader, output io.Writer) error {
	if err := connectorruntime.VerifyDirectory(options.OwnerDirectory); err != nil {
		return err
	}
	project, scope, err := connectionProject(ctx, options.ContextOptions)
	if err != nil {
		return err
	}
	var request connectorruntime.StartRequest
	if connectorruntime.ReadJSON(input, &request) != nil || request.Schema != 1 || !reflect.DeepEqual(request.Context, scope) || (scope.Workload == "") != (request.Assertion == "") {
		return connectorruntime.ErrInvalid
	}
	backend := &nativeConnectionBackend{openSession: o.OpenSession, project: project, scope: scope, stateDir: options.StateDir, assertion: request.Assertion, directory: options.OwnerDirectory, runnerTemp: options.RunnerTemp, parentPID: options.ParentPID}
	if options.ParentPID == 0 {
		backend.initialServices = slices.Clone(scope.Services)
	}
	if options.Manifest != "" {
		m, err := workloadmanifest.Read(options.Manifest)
		if err != nil {
			return err
		}
		backend.acquisition = m.Workloads[scope.Workload].Acquisition
		if backend.acquisition.TokenFile != "" && !filepath.IsAbs(backend.acquisition.TokenFile) {
			backend.acquisition.TokenFile = filepath.Join(scope.Directory, backend.acquisition.TokenFile)
		}
	}
	request.Assertion = ""
	backend.kubeOptions = StartOptions{KubeTokenFile: options.KubeTokenFile, KubeUserConfig: options.KubeUserConfig, KubeUser: options.KubeUser, Namespace: options.Namespace}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	backend.executable = executable
	writer := &connectionReadinessWriter{Writer: output}
	err = connectorruntime.Serve(ctx, scope, options.OwnerDirectory, executable, backend, writer)
	if err != nil && !writer.written {
		reason := Reason(err)
		if reason == "" {
			reason = failure.ConnectionUnavailable
		}
		_ = json.NewEncoder(output).Encode(connectorruntime.Status{Schema: 1, State: "failed", Reason: string(reason)})
	}
	return err
}

type connectionReadinessWriter struct {
	io.Writer
	written bool
}

func (w *connectionReadinessWriter) Write(data []byte) (int, error) {
	w.written = true
	return w.Writer.Write(data)
}
func (w *connectionReadinessWriter) Close() error {
	if closer, ok := w.Writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
func Reason(err error) failure.Reason {
	if err == nil {
		return ""
	}
	if reason, ok := failure.ReasonOf(err); ok {
		return reason
	}
	switch {
	case errors.Is(err, connectorruntime.ErrTeam):
		return failure.ConnectionTeamBinding
	case errors.Is(err, connectorruntime.ErrTransport):
		return failure.ConnectionTransportMissing
	case errors.Is(err, connectorruntime.ErrUnauthorized):
		return failure.ConnectionHandleInvalid
	case errors.Is(err, connectorruntime.ErrExpired):
		return failure.ConnectionExpired
	case errors.Is(err, connectorruntime.ErrInvalid):
		return failure.ConnectionRequestInvalid
	case errors.Is(err, syscall.EADDRINUSE):
		return failure.ConnectionPortInUse
	case errors.Is(err, connectorruntime.ErrCleanup):
		return failure.ConnectionCleanupFailed
	case errors.Is(err, connectorruntime.ErrUnavailable), errors.Is(err, connectorruntime.ErrUnprepared):
		return failure.ConnectionUnavailable
	}
	return ""
}

func KubeCredential(ctx context.Context, path, service string) (credentialv1.ExecCredential, error) {
	h, err := connectorruntime.ReadHandle(path)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	var credential credentialv1.ExecCredential
	if err := connectorruntime.Call(ctx, path, "kube-credential", connectorruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest, Service: service}, &credential); err != nil {
		return credentialv1.ExecCredential{}, err
	}
	return credential, nil
}

func ResolveContext(ctx context.Context, options ContextOptions) (connectorruntime.Context, error) {
	_, scope, err := connectionProject(ctx, options)
	return scope, err
}
