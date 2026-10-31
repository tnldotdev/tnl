package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
)

type fixtureBackend struct {
	startError error
	closed     atomic.Bool
	credential atomic.Int32
	failed     chan error
	deadline   time.Time
	started    chan struct{}
	finished   chan struct{}
}

func (b *fixtureBackend) Start(context.Context) (meta.PublicMetadata, time.Time, error) {
	return meta.PublicMetadata{Namespace: "db.example", Services: map[string]meta.Service{"database": {Protocol: "postgres", Namespace: "example", Hostname: "db.example", Port: 15432, Public: true}}}, b.deadline, b.startError
}
func (b *fixtureBackend) Connect(ctx context.Context, name string) (Connection, error) {
	if b.started != nil {
		close(b.started)
		<-ctx.Done()
		close(b.finished)
		return Connection{}, ctx.Err()
	}
	if name != "database" {
		return Connection{}, ErrInvalid
	}
	b.credential.Add(1)
	return Connection{Schema: 1, Protocol: "postgres", Host: "127.0.0.1", Port: 15432, ExpiresAt: b.deadline, SSL: &TLSOptions{ServerName: "db.example", RejectUnauthorized: true}}, nil
}
func (b *fixtureBackend) Renew(context.Context) (time.Time, error) { return b.deadline, nil }
func (b *fixtureBackend) Prepared(name string) (Connection, error) {
	if name != "database" || b.credential.Load() == 0 {
		return Connection{}, ErrUnprepared
	}
	return Connection{Schema: 1, Protocol: "postgres", Host: "127.0.0.1", Port: 15432, ExpiresAt: b.deadline, SSL: &TLSOptions{ServerName: "db.example", RejectUnauthorized: true}, TransportID: "ctg_aaaaaaaaaaaaaaaaaaaaaa"}, nil
}
func (b *fixtureBackend) Close(context.Context) error { b.closed.Store(true); return nil }
func (b *fixtureBackend) Done() <-chan error          { return b.failed }

func fixtureScope(t *testing.T) Context {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return Context{Schema: 1, Directory: root, ConfigDigest: strings.Repeat("a", 64), Server: "https://control.example", Audience: "https://control.example", ProjectKey: "project-test", SourceID: "source-test", WorktreeKey: "worktree-test", Services: []string{"database"}}
}

func TestConnectionOwnerRenewalOnlyShortensOriginalDeadline(t *testing.T) {
	now := time.Now()
	deadline := now.Add(time.Hour)
	// the remote date can disagree with the running local clock. it must not
	// turn renewal into a new now+remaining countdown in either direction.
	for _, offset := range []time.Duration{-30 * time.Minute, 30 * time.Minute} {
		previous := deadline.Add(offset)
		unchanged, err := renewedOwnerDeadline(now, deadline, previous, previous)
		if err != nil || !unchanged.Equal(deadline) {
			t.Fatal("unchanged authority moved the local deadline", unchanged, err)
		}
		shorter, err := renewedOwnerDeadline(now, deadline, previous, previous.Add(-time.Minute))
		if err != nil || !shorter.Equal(deadline.Add(-time.Minute)) {
			t.Fatal("authority reduction did not shorten the original deadline", shorter, err)
		}
		if _, err := renewedOwnerDeadline(now, deadline, previous, previous.Add(time.Minute)); !errors.Is(err, ErrExpired) {
			t.Fatal("renewal enlarged the execution window", err)
		}
		if _, err := renewedOwnerDeadline(deadline, deadline, previous, previous); !errors.Is(err, ErrExpired) {
			t.Fatal("late renewal revived the expired owner", err)
		}
	}
}

func TestConnectionPreparedReadDoesNotWaitForSiblingNetwork(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &fixtureBackend{deadline: time.Now().Add(time.Hour), started: make(chan struct{}), finished: make(chan struct{})}
	b.credential.Store(1)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); <-done }()
	go func() { done <- Serve(ctx, scope, directory, "/test/tnl", b, writer) }()
	var status Status
	if err := json.NewDecoder(reader).Decode(&status); err != nil {
		t.Fatal(err)
	}
	request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "sibling"}
	stalled := make(chan error, 1)
	go func() { stalled <- Call(ctx, status.ConnectionHandle, "prepare", request, new(Prepared)) }()
	<-b.started
	request.Service = "database"
	bounded, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := Call(bounded, status.ConnectionHandle, "prepared", request, new(Prepared)); err != nil {
		t.Error("prepared sibling waited for unrelated network work", err)
	}
	cancel()
	<-stalled
}

func TestConnectionHandleReadersRejectFIFOWithoutWaitingForWriter(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "handle", true: "stop result"}[stopped], func(t *testing.T) {
			directory, err := NewDirectory(fixtureScope(t).Directory)
			if err != nil {
				t.Fatal(err)
			}
			name := "handle.json"
			if stopped {
				name = "stopped.json"
			}
			path := filepath.Join(directory, name)
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if stopped {
					done <- ReadStopResult(filepath.Join(directory, "handle.json"))
					return
				}
				_, err := ReadHandle(path)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				// unblock the pre-fix reader so a red run leaves no goroutine behind.
				fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
				if err == nil {
					_ = unix.Close(fd)
				}
				<-done
				t.Fatal("reader blocked opening a FIFO before checking its type")
			}
		})
	}
}

type lazyFixtureBackend struct {
	fixtureBackend
	prepared map[string]bool
	network  atomic.Int32
}

func (b *lazyFixtureBackend) Connect(_ context.Context, name string) (Connection, error) {
	b.network.Add(1)
	b.prepared[name] = true
	return Connection{Schema: 1, Protocol: "tcp", Host: "127.0.0.1", Port: 15432, ExpiresAt: b.deadline}, nil
}
func (b *lazyFixtureBackend) Prepared(name string) (Connection, error) {
	if !b.prepared[name] {
		return Connection{}, ErrUnavailable
	}
	return Connection{Schema: 1, Protocol: "tcp", Host: "127.0.0.1", Port: 15432, ExpiresAt: b.deadline}, nil
}

func TestConnectionPreparedSiblingNeverStartsNetworkWork(t *testing.T) {
	scope := fixtureScope(t)
	scope.Services = append(scope.Services, "sibling")
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &lazyFixtureBackend{fixtureBackend: fixtureBackend{deadline: time.Now().Add(time.Hour)}, prepared: map[string]bool{}}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); <-done }()
	go func() { done <- Serve(ctx, scope, directory, "/test/tnl", b, writer) }()
	var status Status
	if err := json.NewDecoder(reader).Decode(&status); err != nil {
		t.Fatal(err)
	}
	request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "sibling"}
	if err := Call(t.Context(), status.ConnectionHandle, "prepared", request, new(Prepared)); err == nil {
		t.Error("synchronous sibling read prepared a service")
	}
	if got := b.network.Load(); got != 0 {
		t.Errorf("synchronous sibling read performed %d network operations; want zero", got)
	}
}

func TestConnectionOwnerTargetTrustsAndJoinedStop(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &fixtureBackend{deadline: time.Now().Add(time.Hour), failed: make(chan error, 1)}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(t.Context(), scope, directory, "/test/tnl", b, writer) }()
	var state Status
	if err := json.NewDecoder(reader).Decode(&state); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(state)
	if bytes.Contains(encoded, []byte("private-snapshot")) || bytes.Contains(encoded, []byte("servername")) {
		t.Fatal("public status leaked private material")
	}
	request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"}
	for i := 1; i <= 2; i++ {
		var snapshot Connection
		if err := Call(t.Context(), state.ConnectionHandle, "connect", request, &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.SSL == nil || snapshot.Host != "127.0.0.1" || snapshot.SSL.ServerName != "db.example" || int(b.credential.Load()) != i {
			t.Fatal("prepared snapshot was cached or lost its managed identity")
		}
	}
	var prepared Prepared
	if err := Call(t.Context(), state.ConnectionHandle, "prepared", request, &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Schema != Schema || prepared.Connection.SSL == nil || prepared.ProjectRuntime.Services["database"].Hostname != prepared.Connection.SSL.ServerName || prepared.Connection.Host != "127.0.0.1" || b.credential.Load() != 2 {
		t.Fatal("prepared read did not pair the same owner's metadata and fresh connection")
	}
	wrong := request
	wrong.Directory += "-other"
	if err := Call(t.Context(), state.ConnectionHandle, "connect", wrong, new(Connection)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("project scope: %v", err)
	}
	if err := Call(t.Context(), state.ConnectionHandle, "stop", request, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not join")
	}
	if !b.closed.Load() {
		t.Fatal("backend still running")
	}
	if _, err := os.Stat(state.ConnectionHandle); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("live handle survived cleanup")
	}
}
func TestConnectionOwnerFailureQuiescesAndSetupAlwaysCloses(t *testing.T) {
	for _, startup := range []bool{false, true} {
		t.Run(map[bool]string{false: "worker", true: "setup"}[startup], func(t *testing.T) {
			scope := fixtureScope(t)
			directory, err := NewDirectory(scope.Directory)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("sensitive provider failure")
			b := &fixtureBackend{deadline: time.Now().Add(time.Hour), failed: make(chan error, 1)}
			if startup {
				b.startError = failure
			}
			reader, writer := io.Pipe()
			done := make(chan error, 1)
			go func() { done <- Serve(t.Context(), scope, directory, "/test/tnl", b, writer) }()
			if !startup {
				var state Status
				if err := json.NewDecoder(reader).Decode(&state); err != nil {
					t.Fatal(err)
				}
				b.failed <- failure
			}
			select {
			case err := <-done:
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("failure left owner running")
			}
			if !b.closed.Load() {
				t.Fatal("partial startup did not close backend")
			}
		})
	}
}
func TestConnectionHandleRejectsSymlinksPermissionsAndExpiry(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "handle.json")
	h := Handle{Schema: 1, URL: "http://127.0.0.1:12345", Key: strings.Repeat("b", 64), Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, ExpiresAt: time.Now().Add(time.Minute), Executable: "/test/tnl"}
	if err := WriteHandle(path, h); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHandle(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHandle(link); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHandle(path); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	h.ExpiresAt = time.Now().Add(-time.Second)
	if err := WriteHandle(path, h); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHandle(path); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
}
func TestConnectionJSONRejectsDuplicateUnknownTrailingAndOversize(t *testing.T) {
	for _, input := range []string{`{"schema":1,"schema":1}`, `{"schema":1,"unknown":true}`, `{"schema":1} {}`, strings.Repeat(" ", MaxBytes+1)} {
		if err := ReadJSON(strings.NewReader(input), new(Request)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid request: %v", err)
		}
	}
}

func TestConnectionStopCancelsHangingCredentialAndJoins(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &fixtureBackend{deadline: time.Now().Add(time.Hour), started: make(chan struct{}), finished: make(chan struct{})}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(t.Context(), scope, directory, "/test/tnl", b, writer) }()
	var state Status
	if err := json.NewDecoder(reader).Decode(&state); err != nil {
		t.Fatal(err)
	}
	request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"}
	requestDone := make(chan error, 1)
	go func() { requestDone <- Call(t.Context(), state.ConnectionHandle, "connect", request, new(Connection)) }()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("credential did not start")
	}
	if err := Call(t.Context(), state.ConnectionHandle, "stop", request, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop waited for the credential timeout")
	}
	select {
	case <-b.finished:
	default:
		t.Fatal("credential still running after stop")
	}
	<-requestDone
	if !b.closed.Load() {
		t.Fatal("backend was not joined")
	}
}

func TestConnectionIPCRejectsWrongProofProjectAndBrowserOrigin(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &fixtureBackend{deadline: time.Now().Add(time.Hour)}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(t.Context(), scope, directory, "/test/tnl", b, writer) }()
	var state Status
	if err := json.NewDecoder(reader).Decode(&state); err != nil {
		t.Fatal(err)
	}
	h, err := ReadHandle(state.ConnectionHandle)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"proof", "project", "origin"} {
		request := Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"}
		if variant == "project" {
			request.Directory += "-other"
		}
		payload, _ := json.Marshal(request)
		req, err := http.NewRequestWithContext(t.Context(), "POST", h.URL+"/v1/connections/connect", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		proof := h.Key
		if variant == "proof" {
			proof = strings.Repeat("0", 64)
		}
		req.Header.Set("Authorization", "Bearer "+proof)
		if variant == "origin" {
			req.Header.Set("Origin", "https://other.example")
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 401 || bytes.Contains(data, []byte(h.Key)) {
			t.Fatal("IPC accepted an unauthorized caller or exposed its proof")
		}
	}
	if b.credential.Load() != 0 {
		t.Fatal("unauthorized IPC exported a credential")
	}
	if err := Call(t.Context(), state.ConnectionHandle, "stop", Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectionAbsoluteDeadlineStopsOwner(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &fixtureBackend{deadline: time.Now().Add(time.Second)}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(t.Context(), scope, directory, "/test/tnl", b, writer) }()
	var state Status
	if err := json.NewDecoder(reader).Decode(&state); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrExpired) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner exceeded its absolute deadline")
	}
	if !b.closed.Load() {
		t.Fatal("deadline did not close the backend")
	}
	if err := ReadStopResult(state.ConnectionHandle); err != nil {
		t.Fatal(err)
	}
}
