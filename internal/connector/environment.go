package connector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// serveEnvironment owns one SDK client's native process. startup is two bounded
// JSON lines: immutable selection, then the response to native's proof challenge.
// callbacks never receive the native session key or visitor credential.
func ServeEnvironment(ctx context.Context, options OwnerServeOptions, input io.ReadCloser, output io.Writer) (result error) {
	if options.ParentPID < 0 || options.ParentPID == 0 && options.OwnerDirectory == "" {
		return connectorruntime.ErrInvalid
	}
	setup, cancelSetup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelSetup()
	stopRead := context.AfterFunc(setup, func() { _ = input.Close() })
	defer stopRead()
	reader := bufio.NewReaderSize(input, connectorruntime.MaxBytes+1)
	read := func(destination any) error {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > connectorruntime.MaxBytes {
			if cause := context.Cause(setup); cause != nil {
				return cause
			}
			return connectorruntime.ErrInvalid
		}
		return connectorruntime.ReadJSON(bytes.NewReader(line), destination)
	}
	var request connectorruntime.EnvironmentStart
	if err := read(&request); err != nil {
		return err
	}
	if request.Schema != connectorruntime.Schema || request.Selection.Validate() != nil || !machineproof.ValidSource(request.Source) {
		return connectorruntime.ErrInvalid
	}
	selection := request.Selection
	directory := options.OwnerDirectory
	var err error
	if directory == "" { directory, err = connectorruntime.NewDirectory(os.TempDir()) } else { err = connectorruntime.VerifyDirectory(directory) }
	if err != nil { return err }
	serving := false
	defer func() {
		// retain failed cleanup evidence; never erase an unjoined owner.
		if options.OwnerDirectory == "" && (!serving || result == nil || result == context.Canceled) {
			result = errors.Join(result, os.RemoveAll(directory))
		}
	}()
	client, err := workload.New(selection.Environment.Server, nil)
	if err != nil {
		return err
	}
	scope := environmentContext(selection, directory)
	configuration := config.TNL{Services: config.Services{}}
	for name, protocol := range selection.Services {
		configuration.Services[name] = config.Service{Protocol: new(protocol)}
	}
	b := &connectorConnectionBackend{scope: scope, project: projectConfiguration{Project: clientproject.Project{Root: directory, Config: configuration}}, directory: directory, parentPID: options.ParentPID}
	if options.ParentPID == 0 { b.initialServices = slices.Clone(scope.Services) }
	b.kubeOptions = StartOptions{KubeTokenFile: options.KubeTokenFile, KubeUserConfig: options.KubeUserConfig, KubeUser: options.KubeUser, Namespace: options.Namespace}
	b.workload = client
	b.environmentSource = request.Source
	if err := b.configureEnvironmentAcquisition(request); err != nil { return err }
	if request.Acquisition == nil {
		challenge, err := b.IdentityChallenge()
		if err != nil { return err }
		if err = json.NewEncoder(output).Encode(challenge); err != nil { return err }
		var proof authorityv1.IdentitySourceReply
		if err := read(&proof); err != nil { return err }
		b.assertion, err = b.consumeEnvironmentReply(proof)
	} else {
		b.assertion, err = b.acquireEnvironmentAssertion(setup)
	}
	if err != nil {
		return err
	}
	stopRead()
	cancelSetup()
	_ = input.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	b.executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	serving = true
	configurationOwner := b.ownerConfig()
	var cleanupComplete *bool
	configurationOwner.Closed = func(err error) { cleanupComplete = new(err == nil) }
	writer := &connectionReadinessWriter{Writer: output}
	result = connectorruntime.Serve(ctx, scope, directory, b.executable, configurationOwner, writer)
	if result != nil && !writer.written {
		reason := Reason(result)
		if reason == "" { reason = failure.ConnectionUnavailable }
		result = errors.Join(result, json.NewEncoder(output).Encode(connectorruntime.Status{Schema:1,State:"failed",PID:os.Getpid(),Executable:b.executable,Reason:string(reason),CleanupComplete:cleanupComplete}))
	}
	return result
}

func environmentContext(selection connectorruntime.EnvironmentSelection, directory string) connectorruntime.Context {
	scopeBytes, _ := json.Marshal(selection)
	digest := sha256.Sum256(scopeBytes)
	return connectorruntime.Context{Schema: 1, Directory: directory, ConfigDigest: hex.EncodeToString(digest[:]), Server: selection.Environment.Server, Audience: selection.Environment.Server, ProjectKey: selection.Environment.ProjectKey, ProjectLabel: selection.Environment.ProjectKey, WorktreeKey: "environment", Services: slices.Sorted(maps.Keys(selection.Services)), Environment: &selection}
}

// startEnvironmentOwner prepares all selected listeners before handing a
// job-owned capability to the caller. source secrets travel through stdin only.
func StartEnvironmentOwner(ctx context.Context, options OwnerStartOptions, input io.Reader, output io.Writer) error {
	var request connectorruntime.EnvironmentStart
	if err := connectorruntime.ReadJSON(input, &request); err != nil { return err }
	if request.Schema != 1 || request.Selection.Validate() != nil || !machineproof.ValidSource(request.Source) || request.Acquisition == nil || options.ParentPID != 0 {
		return connectorruntime.ErrInvalid
	}
	// reject malformed private sources in the caller before detaching. the child
	// repeats this check at acquisition; neither check reads saved provider policy.
	validation := &connectorConnectionBackend{}
	if err := validation.configureEnvironmentAcquisition(request); err != nil {
		return err
	}
	scope := environmentContext(request.Selection, "")
	return launchPreparedOwner(ctx, options, scope, request, func(status connectorruntime.Status) error { return json.NewEncoder(output).Encode(status) })
}

func (b *connectorConnectionBackend) startEnvironment(ctx context.Context) (map[string]controlv1.Service, error) {
	selection := b.scope.Environment
	if selection == nil || selection.Validate() != nil || b.workload == nil {
		return nil, connectorruntime.ErrInvalid
	}
	// retries retain the exact assertion, nonce and ephemeral key. there is no
	// replacement session after expiry and no rediscovery by a logical name.
	prepared, uncertain, err := prepareEnvironment(ctx, b.workload, *selection, b.assertion)
	b.environmentPreparationUncertain = uncertain
	if err != nil {
		if !uncertain { b.assertion = "" }
		return nil, err
	}
	b.deadline = workload.SessionDeadline(prepared.Session)
	b.environmentBinding = &connectorruntime.EnvironmentBinding{Environment: prepared.Environment, AppliedDefinitionRevision: prepared.AppliedDefinitionRevision, MutationRevision: prepared.MutationRevision, Services: prepared.Services}
	b.rememberAssertion(b.assertion, prepared.Session.IdentityExpiresAt, prepared.Session)
	b.assertion = ""
	services := make(map[string]controlv1.Service, len(prepared.Services))
	for name, service := range prepared.Services {
		services[name] = controlv1.Service{Id: service.ServiceId, Name: name, Enabled: true, Protocol: service.Protocol, Endpoint: &service.Endpoint, KubernetesAuth: service.KubernetesAuth}
	}
	return services, nil
}

// a transport failure may hide an already-committed preparation. retry only the
// same full intent, assertion, key and nonce within the original caller budget.
// response validation, denial and caller cancellation are not retry permission.
func prepareEnvironment(ctx context.Context, client *workload.Client, selection connectorruntime.EnvironmentSelection, assertion string) (authorityv1.EnvironmentVisitorPreparation, bool, error) {
	var prepared authorityv1.EnvironmentVisitorPreparation
	var err error
	uncertain := false
	for attempt := range 3 {
		prepared, err = client.Prepare(ctx, selection.Environment, selection.PermissionID, assertion, selection.Services)
		if err == nil { return prepared, false, nil }
		var problem *clientauthority.ProblemError
		if !errors.As(err, &problem) && !errors.Is(err, clientauthority.ErrUnauthenticated) && !errors.Is(err, clientauthority.ErrNotFound) { uncertain = true }
		if attempt == 2 || context.Cause(ctx) != nil || !errors.Is(err, clientauthority.ErrUnavailable) { return prepared, uncertain, err }
	}
	return prepared, uncertain, err
}

func (b *connectorConnectionBackend) EnvironmentBinding() *connectorruntime.EnvironmentBinding {
	if b.environmentBinding == nil {
		return nil
	}
	binding := *b.environmentBinding
	binding.Services = maps.Clone(binding.Services)
	for name, service := range binding.Services {
		if service.KubernetesAuth != nil {
			service.KubernetesAuth = new(*service.KubernetesAuth)
		}
		binding.Services[name] = service
	}
	return &binding
}
