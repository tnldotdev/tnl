package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"golang.org/x/sys/unix"
)

// SDKOptions selects an application-private registry, not a daemon or a shared
// credential. only native operations select, replace and stop its scoped owners.
type SDKOptions struct {
	OwnerStartOptions
	Registry           string
	Service            string
	RecoverHandle      string
	RequestedAt        string
	startedAt          time.Time
	RetainStartFailure bool
	WorkloadSelection  *connectorruntime.SDKWorkloadRequest
	WorkloadPolicy     string
	Environment        *connectorruntime.SDKEnvironment
}

type sdkRegistry struct {
	Schema             int                                               `json:"schema"`
	ParentPID          int                                               `json:"parent_pid"`
	Closed             bool                                              `json:"closed"`
	RetainStartFailure bool                                              `json:"retain_start_failure"`
	Owners             map[string]sdkOwnerRecord                         `json:"owners"`
	Assertions         map[string]connectorruntime.AssertionVerification `json:"assertions"`
}

// an empty owner is a reserved startup or a completed failure, never a visitor
// capability. a failed record keeps its owner until native Stop has joined.
type sdkOwnerRecord struct {
	Owner        connectorruntime.SDKOwner `json:"owner"`
	Failure      failure.Reason            `json:"failure,omitempty"`
	FinishedAt   time.Time                 `json:"finished_at,omitzero"`
	StartFailure bool                      `json:"start_failure,omitempty"`
	Adopted      bool                      `json:"adopted,omitempty"`
}

// keep completed failures for requests delayed before owner selection. language
// and native request deadlines are shorter than this retention window.
const sdkRequestLifetime = 2 * time.Minute

type sdkStartFailure struct {
	error
	retained bool
	handle   string
}

type sdkOwnerFailure struct {
	error
	handle string
}

func (e *sdkOwnerFailure) Unwrap() error          { return e.error }
func (e *sdkOwnerFailure) SDKOwnerHandle() string { return e.handle }

func sdkOwnerError(err error, owner connectorruntime.Status) error {
	if err == nil || owner.ConnectionHandle == "" {
		return err
	}
	return &sdkOwnerFailure{error: err, handle: owner.ConnectionHandle}
}

func (e *sdkStartFailure) Unwrap() error          { return e.error }
func (e *sdkStartFailure) RetainSDKFailure() bool { return e.retained }
func (e *sdkStartFailure) SDKFailureHandle() string {
	if e.retained {
		return e.handle
	}
	return ""
}

func sdkFailureHandle(key string, completed time.Time) string {
	return key + "." + sdkDigest(completed.Format(time.RFC3339Nano))[:16]
}

// the hooks keep selection proofs beside their owner without a subprocess or
// control fixture in every concurrency test. production uses the same operations
// as the caller-prepared CLI and never trusts SDK-decoded assertion claims.
type sdkOperations struct {
	resolve  func(context.Context, ContextOptions) (connectorruntime.Context, error)
	identify func(context.Context, connectorruntime.Context, string) (connectorruntime.AssertionVerification, error)
	start    func(context.Context, OwnerStartOptions, connectorruntime.StartRequest, func(connectorruntime.Status) error) error
	prepare  func(context.Context, connectorruntime.Status, string, string) (connectorruntime.Prepared, error)
	stop     func(context.Context, string) error
	stopped  func(string) error
}

func nativeSDKOperations() sdkOperations {
	return sdkOperations{resolve: ResolveContext, start: launchOwner, stop: Stop, stopped: connectorruntime.OwnerStopped,
		identify: func(ctx context.Context, scope connectorruntime.Context, assertion string) (connectorruntime.AssertionVerification, error) {
			client, err := workload.New(scope.Server, nil)
			if err != nil {
				return connectorruntime.AssertionVerification{}, err
			}
			identity, err := client.IdentifyPolicy(ctx, scope.TeamID, scope.ProjectKey, scope.SourceID, scope.Workload, assertion)
			return connectorruntime.AssertionVerification{Digest: sdkDigest(assertion), Binding: identity.Binding, ExpiresAt: identity.AssertionExpiresAt}, err
		},
		prepare: func(ctx context.Context, owner connectorruntime.Status, service, assertion string) (connectorruntime.Prepared, error) {
			return connectionSnapshot(ctx, owner.ConnectionHandle, service, "prepare", assertion)
		},
	}
}

func sdkDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// PrepareSDK is the private SDK adapter. its short registry lock never covers
// provider/control work or service preparation. each identity has its own startup
// gate; existing native owners retain per-service gates and immutable snapshots.
func PrepareSDK(ctx context.Context, options SDKOptions, input io.Reader) (connectorruntime.SDKPrepared, error) {
	return nativeSDKOperations().prepareSDK(ctx, options, input)
}

func (o sdkOperations) prepareSDK(ctx context.Context, options SDKOptions, input io.Reader) (connectorruntime.SDKPrepared, error) {
	var request struct {
		Schema         int                                  `json:"schema"`
		Assertion      string                               `json:"assertion,omitempty"`
		Workload       *connectorruntime.SDKWorkloadRequest `json:"sdk_workload,omitempty"`
		WorkloadPolicy string                               `json:"sdk_workload_policy,omitempty"`
		Environment    *connectorruntime.SDKEnvironment     `json:"sdk_environment,omitempty"`
	}
	if connectorruntime.ReadJSON(input, &request) != nil || request.Schema != 1 {
		return connectorruntime.SDKPrepared{}, connectorruntime.ErrInvalid
	}
	options.WorkloadSelection, options.WorkloadPolicy, options.Environment = request.Workload, request.WorkloadPolicy, request.Environment
	return o.selectSDK(ctx, options, request.Assertion)
}

func (o sdkOperations) selectSDK(ctx context.Context, options SDKOptions, assertion string) (connectorruntime.SDKPrepared, error) {
	options.startedAt = time.Now()
	if options.RequestedAt != "" {
		requested, err := time.Parse(time.RFC3339Nano, options.RequestedAt)
		if err != nil {
			return connectorruntime.SDKPrepared{}, connectorruntime.ErrInvalid
		}
		options.startedAt = requested
	}
	if options.ParentPID <= 0 || !naming.ValidServiceName(options.Service) || connectorruntime.VerifyDirectory(options.Registry) != nil {
		return connectorruntime.SDKPrepared{}, connectorruntime.ErrInvalid
	}
	if options.RecoverHandle != "" {
		// recovery observes an old child directory, independently of the current
		// index entry. sdkOwner re-reads and proves the current owner under its gate.
		if filepath.Dir(filepath.Dir(options.RecoverHandle)) != options.Registry || filepath.Base(options.RecoverHandle) != "handle.json" {
			return connectorruntime.SDKPrepared{}, connectorruntime.ErrUnauthorized
		}
		if err := o.stopped(options.RecoverHandle); err != nil {
			return connectorruntime.SDKPrepared{}, failure.Wrap("observe SDK owner recovery", failure.ConnectionUnavailable, err)
		}
	}
	var selected workloadmanifest.Selection
	var source string
	if options.WorkloadSelection != nil {
		var err error
		selected, source, err = selectSDKWorkload(options.Directory, options.Service, *options.WorkloadSelection)
		if err != nil {
			return connectorruntime.SDKPrepared{}, err
		}
		if options.WorkloadPolicy != selected.Policy {
			return connectorruntime.SDKPrepared{}, workloadmanifest.ErrInvalid
		}
		options.Workload, options.Manifest = selected.Name, selected.Path
	}
	if options.Workload == "" && assertion != "" {
		return connectorruntime.SDKPrepared{}, connectorruntime.ErrInvalid
	}
	scope, err := o.resolve(ctx, options.ContextOptions)
	if err != nil {
		return connectorruntime.SDKPrepared{}, err
	}
	if options.WorkloadSelection != nil {
		if scope.ConfigDigest != selected.Policy {
			return connectorruntime.SDKPrepared{}, workloadmanifest.ErrInvalid
		}
		environment := connectorruntime.SDKEnvironment{}
		if options.Environment != nil {
			environment = *options.Environment
		}
		assertion, err = acquireSDKWorkload(ctx, selected, source, *options.WorkloadSelection, environment, assertion)
		if err != nil {
			return connectorruntime.SDKPrepared{}, err
		}
	} else if options.Workload != "" && assertion == "" {
		manifest, err := workloadmanifest.Read(options.Manifest)
		if err != nil {
			return connectorruntime.SDKPrepared{}, err
		}
		hints := manifest.Workloads[options.Workload].Acquisition
		if hints.TokenFile != "" && !filepath.IsAbs(hints.TokenFile) {
			hints.TokenFile = filepath.Join(scope.Directory, hints.TokenFile)
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		assertion, err = workload.Acquire(bounded, hints, nil, os.Getenv)
		if err != nil {
			return connectorruntime.SDKPrepared{}, err
		}
	}
	if !slices.Contains(scope.Services, options.Service) {
		return connectorruntime.SDKPrepared{}, connectorruntime.ErrUnauthorized
	}
	scopeBytes, _ := json.Marshal(scope)
	policy := sdkDigest(string(scopeBytes))
	key := policy
	if options.Workload != "" {
		proof, err := o.sdkIdentity(ctx, options, scope, policy, assertion)
		if err != nil {
			return connectorruntime.SDKPrepared{}, err
		}
		key = sdkDigest(policy + proof.Binding)
	}
	owner, created, err := o.sdkOwner(ctx, options, scope, key, assertion)
	if err != nil {
		return connectorruntime.SDKPrepared{}, sdkOwnerError(err, owner)
	}
	prepared, err := o.prepare(ctx, owner, options.Service, assertion)
	if err == nil {
		err = connectorruntime.ValidatePrepared(prepared, options.Service)
	}
	if err == nil && options.Workload != "" {
		proof := prepared.Verification
		if proof == nil || proof.Digest != sdkDigest(assertion) || key != sdkDigest(policy+proof.Binding) {
			err = connectorruntime.ErrInvalid
		}
	}
	if err != nil {
		if errors.Is(err, connectorruntime.ErrInvalid) {
			invalid := failure.Wrap("read native SDK preparation", failure.ServerResponseInvalid, err)
			if !created {
				return connectorruntime.SDKPrepared{}, sdkOwnerError(invalid, owner)
			}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
			defer cancel()
			return connectorruntime.SDKPrepared{}, sdkOwnerError(sdkCleanupFailure(invalid, o.sdkDiscard(cleanup, options, key, owner)), owner)
		}
		// denial, expiry and IPC failure retain the exact owner capability.
		return connectorruntime.SDKPrepared{}, sdkOwnerError(err, owner)
	}
	return connectorruntime.SDKPrepared{Schema: 1, Owner: owner.SDKOwner(), Prepared: prepared}, nil
}

func (o sdkOperations) sdkIdentity(ctx context.Context, options SDKOptions, scope connectorruntime.Context, policy, assertion string) (connectorruntime.AssertionVerification, error) {
	token := sdkDigest(policy + sdkDigest(assertion))
	var proof connectorruntime.AssertionVerification
	load := func(r *sdkRegistry) error {
		if r.Closed {
			return connectorruntime.ErrExpired
		}
		proof = r.Assertions[token]
		return nil
	}
	if err := sdkUpdate(ctx, options, load); err != nil {
		return proof, err
	}
	if proof.ExpiresAt.After(time.Now().Add(time.Second)) {
		return proof, nil
	}
	// warm verified requests skip this gate, including while another assertion
	// for the same policy is stalled at authority.
	gate, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "identity-"+policy+".lock"), os.Getuid())
	if err != nil {
		return proof, err
	}
	defer gate.Close()
	if err := sdkUpdate(ctx, options, load); err != nil || proof.ExpiresAt.After(time.Now().Add(time.Second)) {
		return proof, err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	proof, err = o.identify(bounded, scope, assertion)
	if err != nil {
		return proof, err
	}
	if proof.Digest != sdkDigest(assertion) || len(proof.Binding) != 64 || !proof.ExpiresAt.After(time.Now()) || proof.ExpiresAt.After(time.Now().Add(12*time.Hour+time.Minute)) {
		return proof, connectorruntime.ErrInvalid
	}
	err = sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		for token, p := range r.Assertions {
			if !p.ExpiresAt.After(time.Now()) {
				delete(r.Assertions, token)
			}
		}
		if len(r.Assertions) >= 256 {
			for token := range r.Assertions {
				delete(r.Assertions, token)
				break
			}
		}
		r.Assertions[token] = proof
		return nil
	})
	return proof, err
}

func (o sdkOperations) sdkOwner(ctx context.Context, options SDKOptions, scope connectorruntime.Context, key, assertion string) (connectorruntime.Status, bool, error) {
	gate, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "owner-"+key+".lock"), os.Getuid())
	if err != nil {
		return connectorruntime.Status{}, false, err
	}
	defer gate.Close()
	var record sdkOwnerRecord
	var retained bool
	if err := sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		if r.Closed {
			return connectorruntime.ErrExpired
		}
		record, retained = r.Owners[key], r.RetainStartFailure
		return nil
	}); err != nil {
		return connectorruntime.Status{}, false, err
	}
	owner := connectorruntime.Status{Schema: 1, State: "ready", ConnectionHandle: record.Owner.ConnectionHandle, Executable: record.Owner.Executable, ExpiresAt: record.Owner.ExpiresAt}
	if record.Failure != "" {
		setup := failure.Wrap("prepare SDK owner", record.Failure, connectorruntime.ErrUnavailable)
		if owner.ConnectionHandle != "" {
			if err := o.sdkRetire(ctx, options, key, record); err != nil {
				return owner, false, sdkCleanupFailure(setup, err)
			}
			return owner, false, setup
		}
		if retained && record.StartFailure || !record.FinishedAt.Before(options.startedAt) {
			return owner, false, &sdkStartFailure{error: setup, retained: retained && record.StartFailure, handle: sdkFailureHandle(key, record.FinishedAt)}
		}
	}
	if owner.ConnectionHandle != "" {
		if !owner.ExpiresAt.After(time.Now()) {
			if err := o.stop(ctx, owner.ConnectionHandle); err != nil {
				if errors.Is(err, connectorruntime.ErrInvalid) {
					return owner, false, failure.Wrap("read SDK cleanup acknowledgement", failure.ServerResponseInvalid, err)
				}
				return owner, false, failure.Wrap("join expired SDK owner", failure.ConnectionUnavailable, err)
			}
		} else if o.stopped(owner.ConnectionHandle) != nil {
			// adopting under the startup gate ends the creator's exclusive rollback
			// right before either caller prepares a service outside that gate.
			err := sdkUpdate(ctx, options, func(r *sdkRegistry) error {
				if r.Closed {
					return connectorruntime.ErrExpired
				}
				record.Adopted = true
				r.Owners[key] = record
				return nil
			})
			return owner, false, err
		}
	}
	if err := sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		if r.Closed {
			return connectorruntime.ErrExpired
		}
		for k, previous := range r.Owners {
			if k != key && previous.Failure != "" && previous.Owner.ConnectionHandle == "" && !(r.RetainStartFailure && previous.StartFailure) && time.Since(previous.FinishedAt) > sdkRequestLifetime {
				delete(r.Owners, k)
				continue
			}
			if k != key && previous.Owner.ConnectionHandle != "" && o.stopped(previous.Owner.ConnectionHandle) == nil {
				delete(r.Owners, k)
			}
		}
		if _, exists := r.Owners[key]; !exists && len(r.Owners) >= 32 {
			return connectorruntime.ErrUnavailable
		}
		r.Owners[key] = sdkOwnerRecord{}
		return nil
	}); err != nil {
		return connectorruntime.Status{}, false, err
	}
	start := options.OwnerStartOptions
	start.SDKRegistry = options.Registry
	start.RunnerTemp = options.Registry
	closed := false
	if err := o.start(ctx, start, connectorruntime.StartRequest{Schema: 1, Context: scope, Assertion: assertion}, func(status connectorruntime.Status) error {
		owner = status
		return sdkUpdate(context.WithoutCancel(ctx), options, func(r *sdkRegistry) error {
			closed = r.Closed
			r.Owners[key] = sdkOwnerRecord{Owner: status.SDKOwner()}
			return nil
		})
	}); err != nil {
		completed := time.Now()
		saved := sdkUpdate(context.WithoutCancel(ctx), options, func(r *sdkRegistry) error {
			reason := Reason(err)
			if reason == "" {
				reason = failure.ConnectionUnavailable
			}
			r.Owners[key] = sdkOwnerRecord{Failure: reason, FinishedAt: completed, StartFailure: true}
			return nil
		})
		return connectorruntime.Status{}, false, &sdkStartFailure{error: errors.Join(err, saved), retained: retained && saved == nil, handle: sdkFailureHandle(key, completed)}
	}
	if closed {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		return owner, false, errors.Join(connectorruntime.ErrExpired, o.stop(cleanup, owner.ConnectionHandle))
	}
	return owner, true, nil
}

// SDKPrepare selects the current request's verified owner. any scoped owner can
// carry this operation; the entry handle is not the request's visitor identity.
func (b *connectorConnectionBackend) SDKPrepare(ctx context.Context, request connectorruntime.Request) (connectorruntime.SDKPrepared, error) {
	if b.sdk == nil {
		return connectorruntime.SDKPrepared{}, connectorruntime.ErrInvalid
	}
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return connectorruntime.SDKPrepared{}, err
	}
	defer finish()
	options := *b.sdk
	options.Workload, options.Manifest = request.Workload, request.Manifest
	options.WorkloadSelection, options.WorkloadPolicy, options.Environment = request.SDKWorkload, request.SDKWorkloadPolicy, request.SDKEnvironment
	options.Service = request.Service
	options.RequestedAt = request.RequestedAt
	options.ContextOptions.Service = nil
	operations := nativeSDKOperations()
	if request.Workload == "" && request.SDKWorkload == nil && b.scope.Workload == "" {
		operations.resolve = func(context.Context, ContextOptions) (connectorruntime.Context, error) { return b.scope, nil }
	}
	remote := operations.prepare
	operations.prepare = func(ctx context.Context, owner connectorruntime.Status, service, assertion string) (connectorruntime.Prepared, error) {
		if owner.ConnectionHandle != filepath.Join(b.directory, "handle.json") {
			return remote(ctx, owner, service, assertion)
		}
		return connectorruntime.PrepareSnapshot(ctx, b, connectorruntime.Request{Service: service, Assertion: assertion}, b.ProjectRuntime())
	}
	prepared, err := operations.selectSDK(ctx, options, request.Assertion)
	if err != nil {
		reason := Reason(err)
		if reason == "" {
			reason = failure.ConnectionUnavailable
		}
		err = failure.Wrap("prepare SDK connection", reason, err)
	}
	return prepared, err
}

// StopSDK fences new selections before joining every owner, including a start
// whose preparation failed before the SDK received its first handle.
func StopSDK(ctx context.Context, registry string, parentPID int) error {
	return nativeSDKOperations().stopSDK(ctx, SDKOptions{Registry: registry, OwnerStartOptions: OwnerStartOptions{ParentPID: parentPID}})
}

// CloseSDKFailure releases only the referenced failed startup. an old observation
// cannot clear a replacement, stop a peer, or close the application registry.
func CloseSDKFailure(ctx context.Context, registry string, parentPID int, handle string) error {
	parts := strings.Split(handle, ".")
	if parentPID <= 0 || len(parts) != 2 || len(parts[0]) != 64 || len(parts[1]) != 16 || connectorruntime.VerifyDirectory(registry) != nil {
		return connectorruntime.ErrInvalid
	}
	if _, err := hex.DecodeString(parts[0] + parts[1]); err != nil {
		return connectorruntime.ErrInvalid
	}
	gate, err := filelock.AcquireContext(ctx, filepath.Join(registry, "owner-"+parts[0]+".lock"), os.Getuid())
	if err != nil {
		return err
	}
	defer gate.Close()
	return sdkUpdate(ctx, SDKOptions{Registry: registry, OwnerStartOptions: OwnerStartOptions{ParentPID: parentPID}}, func(r *sdkRegistry) error {
		record, exists := r.Owners[parts[0]]
		if !exists || sdkFailureHandle(parts[0], record.FinishedAt) != handle {
			return nil
		}
		if !record.StartFailure || record.Owner.ConnectionHandle != "" {
			return connectorruntime.ErrUnauthorized
		}
		delete(r.Owners, parts[0])
		return nil
	})
}

func (o sdkOperations) stopSDK(ctx context.Context, options SDKOptions) error {
	if options.ParentPID <= 0 || connectorruntime.VerifyDirectory(options.Registry) != nil {
		return connectorruntime.ErrInvalid
	}
	var keys []string
	if err := sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		r.Closed = true
		for key := range r.Owners {
			keys = append(keys, key)
		}
		return nil
	}); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	errorsByOwner := make([]error, len(keys))
	var workers sync.WaitGroup
	for i, key := range keys {
		workers.Go(func() {
			gate, err := filelock.AcquireContext(bounded, filepath.Join(options.Registry, "owner-"+key+".lock"), os.Getuid())
			if err != nil {
				errorsByOwner[i] = err
				return
			}
			defer gate.Close()
			var owner connectorruntime.SDKOwner
			if err := sdkUpdate(bounded, options, func(r *sdkRegistry) error { owner = r.Owners[key].Owner; return nil }); err != nil {
				errorsByOwner[i] = err
				return
			}
			if owner.ConnectionHandle != "" {
				errorsByOwner[i] = o.stop(bounded, owner.ConnectionHandle)
			}
		})
	}
	workers.Wait()
	return errors.Join(errorsByOwner...)
}

func (o sdkOperations) sdkDiscard(ctx context.Context, options SDKOptions, key string, owner connectorruntime.Status) error {
	gate, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "owner-"+key+".lock"), os.Getuid())
	if err != nil {
		return err
	}
	defer gate.Close()
	var record sdkOwnerRecord
	if err := sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		current := r.Owners[key]
		if current.Owner.ConnectionHandle != owner.ConnectionHandle || current.Adopted {
			return nil
		}
		record = sdkOwnerRecord{Owner: owner.SDKOwner(), Failure: failure.ServerResponseInvalid}
		r.Owners[key] = record
		return nil
	}); err != nil {
		return err
	}
	if record.Owner.ConnectionHandle == "" {
		return nil
	}
	return o.sdkRetire(ctx, options, key, record)
}

// callers hold this identity's gate. Stop is the existing joined cleanup path;
// only its successful completion clears a capability from the registry.
func (o sdkOperations) sdkRetire(ctx context.Context, options SDKOptions, key string, record sdkOwnerRecord) error {
	if err := o.stop(ctx, record.Owner.ConnectionHandle); err != nil {
		return err
	}
	return sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		if r.Owners[key].Owner.ConnectionHandle == record.Owner.ConnectionHandle {
			r.Owners[key] = sdkOwnerRecord{Failure: record.Failure, FinishedAt: time.Now()}
		}
		return nil
	})
}

func sdkCleanupFailure(setup, cleanup error) error {
	if cleanup == nil {
		return setup
	}
	return failure.Wrap("join SDK owner cleanup", failure.ConnectionCleanupFailed, errors.Join(setup, cleanup))
}

// sdkUpdate protects only local publication. the application supplies a private
// directory; no assertion, signing key or session credential is persisted here.
func sdkUpdate(ctx context.Context, options SDKOptions, update func(*sdkRegistry) error) error {
	lock, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "registry.lock"), os.Getuid())
	if err != nil {
		return err
	}
	defer lock.Close()
	path := filepath.Join(options.Registry, "registry.json")
	r := sdkRegistry{Schema: 1, ParentPID: options.ParentPID, RetainStartFailure: options.RetainStartFailure, Owners: map[string]sdkOwnerRecord{}, Assertions: map[string]connectorruntime.AssertionVerification{}}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	existed := err == nil
	if err == nil {
		f := os.NewFile(uintptr(fd), path)
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > connectorruntime.MaxBytes || connectorruntime.ReadJSON(f, &r) != nil || r.Schema != 1 || r.ParentPID != options.ParentPID || r.Owners == nil || r.Assertions == nil || len(r.Owners) > 32 || len(r.Assertions) > 256 {
			return connectorruntime.ErrUnauthorized
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	before, _ := json.Marshal(r)
	if err := update(&r); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > connectorruntime.MaxBytes {
		return connectorruntime.ErrInvalid
	}
	if existed && bytes.Equal(before, data) {
		return nil
	}
	f, err := os.CreateTemp(options.Registry, "registry-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
