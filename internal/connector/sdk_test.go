package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

type sdkTestOwner struct {
	listener net.Listener
	lock     *filelock.Lock
	status   connectorruntime.Status
	closed   bool
}

type sdkFixture struct {
	mu                                  sync.Mutex
	options                             SDKOptions
	operations                          sdkOperations
	owners                              map[string]*sdkTestOwner
	identified, started, stopped        int
	denyStart                           bool
	prepareError                        error
	invalid                             bool
	blockedService                      string
	prepareGate, identityGate, stopGate <-chan struct{}
	preparing, identifying, stopping    chan struct{}
}

func newSDKFixture(t *testing.T, workload bool) *sdkFixture {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := connectorruntime.NewDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	f := &sdkFixture{options: SDKOptions{OwnerStartOptions: OwnerStartOptions{ContextOptions: ContextOptions{Directory: directory}, ParentPID: os.Getpid()}, Registry: registry, Service: "db"}, owners: map[string]*sdkTestOwner{}}
	if workload {
		f.options.Workload = "job"
	}
	f.operations = sdkOperations{
		resolve: func(_ context.Context, options ContextOptions) (connectorruntime.Context, error) {
			return connectorruntime.Context{Schema: 1, Directory: options.Directory, ConfigDigest: strings.Repeat("c", 64), Server: "https://control.example", Workload: options.Workload, Services: []string{"db", "sibling"}}, nil
		},
		identify: func(ctx context.Context, _ connectorruntime.Context, assertion string) (connectorruntime.AssertionVerification, error) {
			f.mu.Lock()
			f.identified++
			gate, entered := f.identityGate, f.identifying
			f.mu.Unlock()
			if entered != nil {
				select {
				case entered <- struct{}{}:
				default:
				}
			}
			if gate != nil {
				select {
				case <-gate:
				case <-ctx.Done():
					return connectorruntime.AssertionVerification{}, ctx.Err()
				}
			}
			if assertion == "forged" {
				return connectorruntime.AssertionVerification{}, connectorruntime.ErrUnauthorized
			}
			binding := strings.Repeat("a", 64)
			if assertion == "other" {
				binding = strings.Repeat("b", 64)
			}
			return connectorruntime.AssertionVerification{Digest: sdkDigest(assertion), Binding: binding, ExpiresAt: time.Now().Add(time.Minute)}, nil
		},
		start: func(_ context.Context, options OwnerStartOptions, _ connectorruntime.StartRequest, accept func(connectorruntime.Status) error) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.started++
			if f.denyStart {
				return connectorruntime.ErrUnauthorized
			}
			dir, err := connectorruntime.NewDirectory(options.RunnerTemp)
			if err != nil {
				return err
			}
			lock, err := filelock.Acquire(filepath.Join(dir, "owner.lock"), filelock.Nonblocking, os.Getuid())
			if err != nil {
				return err
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				lock.Close()
				return err
			}
			status := connectorruntime.Status{Schema: 1, State: "ready", PID: os.Getpid(), ExpiresAt: time.Now().Add(time.Hour), ConnectionHandle: filepath.Join(dir, "handle.json"), Executable: "/installed/tnl"}
			f.owners[status.ConnectionHandle] = &sdkTestOwner{listener: listener, lock: lock, status: status}
			return accept(status)
		},
		prepare: func(ctx context.Context, owner connectorruntime.Status, service, assertion string) (connectorruntime.Prepared, error) {
			f.mu.Lock()
			gate, entered := f.prepareGate, f.preparing
			if service != f.blockedService {
				gate = nil
				entered = nil
			}
			failure, invalid := f.prepareError, f.invalid
			f.mu.Unlock()
			if entered != nil {
				select {
				case entered <- struct{}{}:
				default:
				}
			}
			if gate != nil {
				select {
				case <-gate:
				case <-ctx.Done():
					return connectorruntime.Prepared{}, ctx.Err()
				}
			}
			if failure != nil {
				return connectorruntime.Prepared{}, failure
			}
			metadata := meta.PublicMetadata{Namespace: "example.test", Services: map[string]meta.Service{}}
			for _, name := range []string{"db", "sibling"} {
				endpoint, _ := meta.NewEndpoint("example.test", name+".example.test", "postgres", 15443, false)
				metadata.Services[name] = endpoint
			}
			p := connectorruntime.Prepared{Schema: 1, ProjectRuntime: metadata, Connection: connectorruntime.Connection{Schema: 1, Protocol: "postgres", Host: "127.0.0.1", Port: 12345, SSL: &connectorruntime.TLSOptions{ServerName: service + ".example.test", RejectUnauthorized: true}, ExpiresAt: time.Now().Add(time.Minute), TransportID: "ctg_" + strings.Repeat("a", 22)}}
			if invalid {
				p.Schema = 2
			}
			if assertion != "" {
				binding := strings.Repeat("a", 64)
				if assertion == "other" {
					binding = strings.Repeat("b", 64)
				}
				p.Verification = &connectorruntime.AssertionVerification{Digest: sdkDigest(assertion), Binding: binding, ExpiresAt: time.Now().Add(time.Minute)}
			}
			return p, nil
		},
		stop: func(ctx context.Context, file string) error {
			f.mu.Lock()
			f.stopped++
			gate, entered := f.stopGate, f.stopping
			f.mu.Unlock()
			if entered != nil {
				select {
				case entered <- struct{}{}:
				default:
				}
			}
			if gate != nil {
				select {
				case <-gate:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			owner := f.owners[file]
			if owner != nil && !owner.closed {
				owner.listener.Close()
				owner.lock.Close()
				owner.closed = true
			}
			return nil
		},
		stopped: connectorruntime.OwnerStopped,
	}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, owner := range f.owners {
			owner.listener.Close()
			owner.lock.Close()
		}
	})
	return f
}

func (f *sdkFixture) prepare(ctx context.Context, assertion, service string) (connectorruntime.SDKPrepared, error) {
	options := f.options
	options.Service = service
	data, _ := json.Marshal(map[string]any{"schema": 1, "assertion": assertion})
	return f.operations.prepareSDK(ctx, options, bytes.NewReader(data))
}

func TestConnectionSDKVerifiedSelectionBudgetAndIsolation(t *testing.T) {
	f := newSDKFixture(t, true)
	first, err := f.prepare(t.Context(), "first", "db")
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		warm, err := f.prepare(t.Context(), "first", "db")
		if err != nil || warm.Owner.ConnectionHandle != first.Owner.ConnectionHandle {
			t.Fatal("warm selection changed owner", err)
		}
	}
	if f.identified != 1 || f.started != 1 {
		t.Fatal("warm selection repeated control/start work", f.identified, f.started)
	}
	rotated, err := f.prepare(t.Context(), "rotated", "sibling")
	if err != nil || rotated.Owner.ConnectionHandle != first.Owner.ConnectionHandle || f.identified != 2 {
		t.Fatal("rotation lost verified binding", err)
	}
	if _, err := f.prepare(t.Context(), "forged", "db"); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("unverified assertion selected cached owner", err)
	}
	other, err := f.prepare(t.Context(), "other", "db")
	if err != nil || other.Owner.ConnectionHandle == first.Owner.ConnectionHandle {
		t.Fatal("subjects shared an owner", err)
	}
	data, err := os.ReadFile(filepath.Join(f.options.Registry, "registry.json"))
	if err != nil || bytes.Contains(data, []byte("rotated")) || bytes.Contains(data, []byte("first")) || bytes.Contains(data, []byte("forged")) {
		t.Fatal("registry retained assertion bytes", err)
	}
	// no SDK-decoded identity cache remains. warm requests skip an unrelated
	// authority stall, and a stalled service cannot hold its sibling's gate.
	identityGate, prepareGate := make(chan struct{}), make(chan struct{})
	f.mu.Lock()
	f.identityGate, f.identifying = identityGate, make(chan struct{}, 1)
	f.prepareGate, f.preparing, f.blockedService = prepareGate, make(chan struct{}, 1), "sibling"
	f.mu.Unlock()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); _, _ = f.prepare(t.Context(), "new", "db") }()
	<-f.identifying
	go func() { defer workers.Done(); _, _ = f.prepare(t.Context(), "first", "sibling") }()
	<-f.preparing
	bounded, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := f.prepare(bounded, "first", "db"); err != nil {
		t.Error("stalled sibling or assertion blocked a verified warm request", err)
	}
	close(identityGate)
	close(prepareGate)
	workers.Wait()
}

func TestConnectionSDKConcurrentDeathAndExpiryRecovery(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "crash"}[crash], func(t *testing.T) {
			f := newSDKFixture(t, false)
			first, err := f.prepare(t.Context(), "", "db")
			if err != nil {
				t.Fatal(err)
			}
			if crash {
				f.owners[first.Owner.ConnectionHandle].lock.Close()
			} else {
				if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
					for key, owner := range r.Owners {
						owner.Owner.ExpiresAt = time.Now().Add(-time.Second)
						r.Owners[key] = owner
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			var workers sync.WaitGroup
			files := make(chan string, 8)
			for range 8 {
				workers.Go(func() {
					current, err := f.prepare(t.Context(), "", "db")
					if err != nil {
						t.Error(err)
						return
					}
					files <- current.Owner.ConnectionHandle
				})
			}
			workers.Wait()
			close(files)
			var selected string
			for file := range files {
				if selected == "" {
					selected = file
				}
				if selected != file || file == first.Owner.ConnectionHandle {
					t.Error("concurrent recovery duplicated or retained old owner")
				}
			}
			if f.started != 2 {
				t.Fatal("recovery started multiple owners", f.started)
			}
			if !crash && !f.owners[first.Owner.ConnectionHandle].closed {
				t.Fatal("replacement preceded joined cleanup")
			}
		})
	}
}

func TestConnectionSDKLiveFailureCannotProveDeath(t *testing.T) {
	f := newSDKFixture(t, false)
	first, err := f.prepare(t.Context(), "", "db")
	if err != nil {
		t.Fatal(err)
	}
	f.prepareError = connectorruntime.ErrUnavailable
	if _, err := f.prepare(t.Context(), "", "db"); !errors.Is(err, connectorruntime.ErrUnavailable) {
		t.Fatal(err)
	}
	f.prepareError = nil
	current, err := f.prepare(t.Context(), "", "db")
	if err != nil || current.Owner.ConnectionHandle != first.Owner.ConnectionHandle || f.started != 1 || f.stopped != 0 {
		t.Fatal("IPC failure replaced live owner", err)
	}
	// malformed recovery/cleanup evidence is not permission to replace either.
	f.operations.stopped = func(string) error { return connectorruntime.ErrCleanup }
	if _, err := f.prepare(t.Context(), "", "db"); err != nil || f.started != 1 {
		t.Fatal("invalid recovery proof replaced owner", err)
	}
}

func TestConnectionSDKCleanupMustJoinBeforeReplacement(t *testing.T) {
	f := newSDKFixture(t, false)
	f.invalid = true
	gate := make(chan struct{})
	f.stopGate, f.stopping = gate, make(chan struct{}, 1)
	first := make(chan error, 1)
	go func() { _, err := f.prepare(t.Context(), "", "db"); first <- err }()
	<-f.stopping
	f.mu.Lock()
	starts := f.started
	f.mu.Unlock()
	if starts != 1 {
		t.Fatal("unexpected startup count", starts)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if _, err := f.prepare(ctx, "", "db"); err == nil {
		t.Fatal("replacement skipped held cleanup")
	}
	f.mu.Lock()
	starts = f.started
	f.invalid = false
	f.mu.Unlock()
	if starts != 1 {
		t.Fatal("replacement started before joined stop", starts)
	}
	close(gate)
	if !errors.Is(<-first, connectorruntime.ErrInvalid) {
		t.Fatal("invalid snapshot lost its error")
	}
	if _, err := f.prepare(t.Context(), "", "db"); err != nil {
		t.Fatal(err)
	}
	if f.started != 2 {
		t.Fatal("cleanup did not permit one replacement", f.started)
	}
}

func TestConnectionSDKRegistryCapacityAndReclamation(t *testing.T) {
	f := newSDKFixture(t, false)
	for range 40 {
		current, err := f.prepare(t.Context(), "", "db")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.operations.stop(t.Context(), current.Owner.ConnectionHandle); err != nil {
			t.Fatal(err)
		}
	}
	if f.started != 40 {
		t.Fatal("stopped owner was reused", f.started)
	}
	// active distinct contexts remain bounded, without a lifetime limit on
	// sequential manifests that have already joined their owners.
	resolve := f.operations.resolve
	for i := range 32 {
		f.operations.resolve = func(ctx context.Context, options ContextOptions) (connectorruntime.Context, error) {
			scope, err := resolve(ctx, options)
			scope.ConfigDigest = sdkDigest(string(rune(i)))
			return scope, err
		}
		if _, err := f.prepare(t.Context(), "", "db"); err != nil {
			t.Fatal(err)
		}
	}
	f.operations.resolve = func(ctx context.Context, options ContextOptions) (connectorruntime.Context, error) {
		scope, err := resolve(ctx, options)
		scope.ConfigDigest = sdkDigest("overflow")
		return scope, err
	}
	if _, err := f.prepare(t.Context(), "", "db"); !errors.Is(err, connectorruntime.ErrUnavailable) {
		t.Fatal("active capacity was unbounded", err)
	}
	for file, owner := range f.owners {
		if !owner.closed {
			if err := f.operations.stop(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if _, err := f.prepare(t.Context(), "", "db"); err != nil {
		t.Fatal("joined owner did not release active capacity", err)
	}
}

func TestConnectionSDKIdentityWaitersAdoptReplacementAfterClose(t *testing.T) {
	f := newSDKFixture(t, true)
	first, err := f.prepare(t.Context(), "first", "db")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	f.identityGate, f.identifying = release, make(chan struct{}, 1)
	files := make(chan string, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			prepared, err := f.prepare(t.Context(), "rotated", "db")
			if err != nil {
				t.Error(err)
				return
			}
			files <- prepared.Owner.ConnectionHandle
		})
	}
	<-f.identifying
	if err := f.operations.stop(t.Context(), first.Owner.ConnectionHandle); err != nil {
		t.Fatal(err)
	}
	replacement, err := f.prepare(t.Context(), "first", "sibling")
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	workers.Wait()
	close(files)
	for file := range files {
		if file != replacement.Owner.ConnectionHandle {
			t.Fatal("identity waiter lost the replacement after joined close")
		}
	}
	if f.started != 2 || f.identified != 2 {
		t.Fatal("identity waiters repeated selection or startup", f.started, f.identified)
	}
}

func TestConnectionSDKColdFailureIsOneAttemptForConcurrentWaiters(t *testing.T) {
	f := newSDKFixture(t, false)
	f.denyStart = true
	f.options.RequestedAt = time.Now().Format(time.RFC3339Nano)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if _, err := f.prepare(t.Context(), "", "db"); err == nil || Reason(err) != failure.ConnectionHandleInvalid {
				t.Error("startup denial lost its owned classification", err)
			}
		})
	}
	workers.Wait()
	if f.started != 1 {
		t.Fatalf("one failed startup became %d attempts", f.started)
	}
	f.options.RequestedAt = time.Now().Format(time.RFC3339Nano)
	f.denyStart = false
	if _, err := f.prepare(t.Context(), "", "db"); err != nil || f.started != 2 {
		t.Fatal("an explicit later attempt could not retry", err, f.started)
	}
}

func TestConnectionSDKPythonRetainsStartupFailureUntilClosed(t *testing.T) {
	f := newSDKFixture(t, false)
	f.options.RetainStartFailure = true
	f.denyStart = true
	if _, err := f.prepare(t.Context(), "", "db"); err == nil {
		t.Fatal("startup denial was accepted")
	}
	f.denyStart = false
	for range 8 {
		if _, err := f.prepare(t.Context(), "", "db"); err == nil || Reason(err) != failure.ConnectionHandleInvalid {
			t.Fatal("a retained denial was retried or reclassified", err)
		}
	}
	if f.started != 1 {
		t.Fatal("retained denial repeated authentication", f.started)
	}
	if err := f.operations.stopSDK(t.Context(), f.options); err != nil {
		t.Fatal(err)
	}
	registry, err := connectorruntime.NewDirectory(filepath.Dir(f.options.Registry))
	if err != nil {
		t.Fatal(err)
	}
	f.options.Registry = registry
	if _, err := f.prepare(t.Context(), "", "db"); err != nil || f.started != 2 {
		t.Fatal("closing did not release the failed scope", err)
	}
}

func TestConnectionSDKClosingFailureLeavesPeerAndReplacementUntouched(t *testing.T) {
	f := newSDKFixture(t, true)
	f.options.RetainStartFailure = true
	f.denyStart = true
	_, err := f.prepare(t.Context(), "first", "db")
	var failed interface{ SDKFailureHandle() string }
	if !errors.As(err, &failed) || failed.SDKFailureHandle() == "" {
		t.Fatal("retained failure has no native close reference", err)
	}
	old := failed.SDKFailureHandle()
	f.denyStart = false
	peer, err := f.prepare(t.Context(), "other", "db")
	if err != nil {
		t.Fatal(err)
	}
	if err := CloseSDK(t.Context(), SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID + 1, FailureHandle: old}); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("another parent cleared failure", err)
	}
	if err := CloseSDK(t.Context(), SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, FailureHandle: old}); err != nil {
		t.Fatal(err)
	}
	current, err := f.prepare(t.Context(), "first", "db")
	if err != nil || f.started != 3 {
		t.Fatal("closing failed identity did not permit retry", err, f.started)
	}
	if err := CloseSDK(t.Context(), SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, FailureHandle: old}); err != nil {
		t.Fatal(err)
	}
	warm, err := f.prepare(t.Context(), "first", "db")
	if err != nil || warm.Owner.ConnectionHandle != current.Owner.ConnectionHandle || f.stopped != 0 {
		t.Fatal("old failure reference affected replacement", err)
	}
	other, err := f.prepare(t.Context(), "other", "sibling")
	if err != nil || other.Owner.ConnectionHandle != peer.Owner.ConnectionHandle || f.stopped != 0 {
		t.Fatal("failure close affected peer", err)
	}
	// a later failure for the same key is a different observation too.
	if err := f.operations.stop(t.Context(), current.Owner.ConnectionHandle); err != nil {
		t.Fatal(err)
	}
	f.denyStart = true
	_, err = f.prepare(t.Context(), "first", "db")
	if !errors.As(err, &failed) || failed.SDKFailureHandle() == old {
		t.Fatal("new startup reused failure reference", err)
	}
	if err := CloseSDK(t.Context(), SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, FailureHandle: old}); err != nil {
		t.Fatal(err)
	}
	f.denyStart = false
	if _, err := f.prepare(t.Context(), "first", "db"); err == nil || f.started != 4 {
		t.Fatal("old close cleared a newer failure", err, f.started)
	}
}

func TestConnectionSDKCloseBeforeFirstHandleRetainsFailedCleanup(t *testing.T) {
	f := newSDKFixture(t, false)
	start := f.operations.start
	entered, release := make(chan struct{}), make(chan struct{})
	f.operations.start = func(ctx context.Context, options OwnerStartOptions, input connectorruntime.StartRequest, accept func(connectorruntime.Status) error) error {
		close(entered)
		<-release
		return start(ctx, options, input, accept)
	}
	stop := f.operations.stop
	cleanupFailure := errors.New("private cleanup failure")
	f.operations.stop = func(context.Context, string) error { return cleanupFailure }
	prepared := make(chan error, 1)
	go func() { _, err := f.prepare(t.Context(), "", "db"); prepared <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if err := f.operations.stopSDK(ctx, f.options); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close did not wait for pending startup", err)
	}
	close(release)
	err := <-prepared
	if !errors.Is(err, connectorruntime.ErrExpired) || !errors.Is(err, cleanupFailure) {
		t.Fatal("late startup lost cancellation or cleanup failure", err)
	}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		for _, owner := range r.Owners {
			if owner.Owner.ConnectionHandle != "" {
				return nil
			}
		}
		return errors.New("late owner capability was discarded before cleanup joined")
	}); err != nil {
		t.Fatal(err)
	}
	f.operations.stop = stop
	if err := f.operations.stopSDK(t.Context(), f.options); err != nil {
		t.Fatal("close could not retry joined cleanup", err)
	}
	for _, owner := range f.owners {
		if !owner.closed {
			t.Fatal("retry left an owner running")
		}
	}
	if _, err := f.prepare(t.Context(), "", "db"); !errors.Is(err, connectorruntime.ErrExpired) || f.started != 1 {
		t.Fatal("closed scope resurrected a pending owner", err)
	}
}

func TestConnectionSDKRollbackCleanupHasBothCausesAndStableReason(t *testing.T) {
	f := newSDKFixture(t, false)
	f.invalid = true
	cleanupFailure := errors.New("private cleanup cause")
	f.operations.stop = func(context.Context, string) error { return cleanupFailure }
	_, err := f.prepare(t.Context(), "", "db")
	if !errors.Is(err, connectorruntime.ErrInvalid) || !errors.Is(err, cleanupFailure) || Reason(err) != failure.ConnectionCleanupFailed {
		t.Fatal("rollback lost a cause or cleanup classification", err, Reason(err))
	}
	if f.started != 1 {
		t.Fatal("invalid setup started a replacement")
	}
}

func TestConnectionSDKLateKernelRecoveryAdoptsCurrentReplacement(t *testing.T) {
	f := newSDKFixture(t, false)
	first, err := f.prepare(t.Context(), "", "db")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.operations.stop(t.Context(), first.Owner.ConnectionHandle); err != nil {
		t.Fatal(err)
	}
	f.options.RecoverHandle = first.Owner.ConnectionHandle
	current, err := f.prepare(t.Context(), "", "db")
	if err != nil {
		t.Fatal(err)
	}
	late, err := f.prepare(t.Context(), "", "sibling")
	if err != nil || late.Owner.ConnectionHandle != current.Owner.ConnectionHandle || f.started != 2 {
		t.Fatal("a late OS death observation lost the current replacement", err, f.started)
	}
}

func TestConnectionSDKWarmMalformedSnapshotDoesNotRetireSibling(t *testing.T) {
	f := newSDKFixture(t, false)
	first, err := f.prepare(t.Context(), "", "db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepare(t.Context(), "", "sibling"); err != nil {
		t.Fatal(err)
	}
	f.invalid = true
	if _, err := f.prepare(t.Context(), "", "db"); err == nil {
		t.Fatal("malformed warm metadata was accepted")
	}
	f.invalid = false
	sibling, err := f.prepare(t.Context(), "", "sibling")
	if err != nil || sibling.Owner.ConnectionHandle != first.Owner.ConnectionHandle || f.stopped != 0 {
		t.Fatal("malformed warm metadata retired an established sibling", err, f.stopped)
	}
}

func TestConnectionSDKMalformedCreatorCannotRetireAdoptedSibling(t *testing.T) {
	f := newSDKFixture(t, false)
	prepare := f.operations.prepare
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finished := make(chan struct{})
	defer func() { releaseOnce.Do(func() { close(release) }); <-finished }()
	f.operations.prepare = func(ctx context.Context, owner connectorruntime.Status, service, assertion string) (connectorruntime.Prepared, error) {
		if service == "db" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return connectorruntime.Prepared{}, ctx.Err()
			}
		}
		prepared, err := prepare(ctx, owner, service, assertion)
		if service == "db" {
			prepared.Schema = 2
		}
		return prepared, err
	}
	creator := make(chan error, 1)
	go func() { defer close(finished); _, err := f.prepare(t.Context(), "", "db"); creator <- err }()
	<-entered
	// the sibling must finish while the creator's first preparation is held;
	// keeping the startup gate through validation would deadlock this boundary.
	bounded, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	sibling, err := f.prepare(bounded, "", "sibling")
	if err != nil {
		t.Fatal("held first preparation blocked its sibling", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-creator; !errors.Is(err, connectorruntime.ErrInvalid) || Reason(err) != failure.ServerResponseInvalid {
		t.Fatal("creator lost its malformed snapshot classification", err)
	}
	owner := f.owners[sibling.Owner.ConnectionHandle]
	if f.started != 1 || f.stopped != 0 || owner.closed || connectorruntime.OwnerStopped(sibling.Owner.ConnectionHandle) == nil {
		t.Fatal("malformed creator retired its adopted sibling", f.started, f.stopped, owner.closed)
	}
	current, err := f.prepare(t.Context(), "", "sibling")
	if err != nil || current.Owner.ConnectionHandle != sibling.Owner.ConnectionHandle || f.started != 1 {
		t.Fatal("malformed creator poisoned its sibling's index entry", err, f.started)
	}
}

func TestConnectionSDKNativeValidationOwnsCreationRollback(t *testing.T) {
	for name, corrupt := range map[string]func(*connectorruntime.Prepared){
		"schema":    func(p *connectorruntime.Prepared) { p.Schema = 2 },
		"metadata":  func(p *connectorruntime.Prepared) { p.ProjectRuntime.Services["db"] = meta.Service{} },
		"host":      func(p *connectorruntime.Prepared) { p.Connection.Host = "db.example.test" },
		"port":      func(p *connectorruntime.Prepared) { p.Connection.Port = 0 },
		"tls":       func(p *connectorruntime.Prepared) { p.Connection.SSL.RejectUnauthorized = false },
		"identity":  func(p *connectorruntime.Prepared) { p.Connection.SSL.ServerName = "other.example.test" },
		"transport": func(p *connectorruntime.Prepared) { p.Connection.TransportID = "bad" },
		"url":       func(p *connectorruntime.Prepared) { p.Connection.URL = "https://other.example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSDKFixture(t, false)
			prepare := f.operations.prepare
			f.operations.prepare = func(ctx context.Context, owner connectorruntime.Status, service, assertion string) (connectorruntime.Prepared, error) {
				p, err := prepare(ctx, owner, service, assertion)
				corrupt(&p)
				return p, err
			}
			if _, err := f.prepare(t.Context(), "", "db"); !errors.Is(err, connectorruntime.ErrInvalid) {
				t.Fatal("malformed creation was accepted", err)
			}
			if f.started != 1 || f.stopped != 1 {
				t.Fatal("native validation did not join exactly its creation", f.started, f.stopped)
			}
			for _, owner := range f.owners {
				if !owner.closed {
					t.Fatal("invalid native creation remained live")
				}
			}
		})
	}
}

func TestConnectionSDKExpiredCleanupAndAuthenticationCannotBeBypassed(t *testing.T) {
	f := newSDKFixture(t, false)
	first, err := f.prepare(t.Context(), "", "db")
	if err != nil {
		t.Fatal(err)
	}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		for key, record := range r.Owners {
			record.Owner.ExpiresAt = time.Now().Add(-time.Second)
			r.Owners[key] = record
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stop := f.operations.stop
	f.operations.stop = func(context.Context, string) error { return connectorruntime.ErrInvalid }
	if _, err := f.prepare(t.Context(), "", "db"); !errors.Is(err, connectorruntime.ErrInvalid) || Reason(err) != failure.ServerResponseInvalid || f.started != 1 {
		t.Fatal("invalid cleanup acknowledgement permitted replacement", err)
	}
	if f.owners[first.Owner.ConnectionHandle].closed {
		t.Fatal("failed cleanup lost its owner capability")
	}
	f.operations.stop = stop
	f.denyStart = true
	f.options.RetainStartFailure = true
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error { r.RetainStartFailure = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepare(t.Context(), "", "db"); err == nil {
		t.Fatal("replacement reused old authentication")
	}
	for range 8 {
		if _, err := f.prepare(t.Context(), "", "db"); err == nil {
			t.Fatal("denied authentication was retried")
		}
	}
	if f.started != 2 || !f.owners[first.Owner.ConnectionHandle].closed {
		t.Fatal("denied replacement did not follow one joined cleanup", f.started)
	}
}

func TestConnectionSDKFailedIdentityPoliciesCannotConsumeOwnerCapacity(t *testing.T) {
	for _, invalid := range []string{"denied", "expired", "digest", "binding"} {
		f := newSDKFixture(t, true)
		identify := f.operations.identify
		f.operations.identify = func(ctx context.Context, scope connectorruntime.Context, assertion string) (connectorruntime.AssertionVerification, error) {
			if invalid == "denied" {
				return connectorruntime.AssertionVerification{}, connectorruntime.ErrUnauthorized
			}
			proof, err := identify(ctx, scope, assertion)
			switch invalid {
			case "expired":
				proof.ExpiresAt = time.Now().Add(-time.Second)
			case "digest":
				proof.Digest = "wrong"
			case "binding":
				proof.Binding = "wrong"
			}
			return proof, err
		}
		for i := range 40 {
			f.options.Directory = filepath.Join(filepath.Dir(f.options.Registry), sdkDigest(string(rune(i))))
			if _, err := f.prepare(t.Context(), "first", "db"); err == nil {
				t.Fatal("invalid identity was accepted")
			}
		}
		if f.started != 0 {
			t.Fatal("failed identity opened an owner")
		}
		f.operations.identify = identify
		if _, err := f.prepare(t.Context(), "first", "db"); err != nil {
			t.Fatal("inactive denied policies exhausted selection", err)
		}
	}
}
