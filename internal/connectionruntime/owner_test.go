package connectionruntime

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

	"github.com/tnldotdev/tnl/internal/projectmeta"
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

func (b *fixtureBackend) Start(context.Context) (projectmeta.PublicMetadata, time.Time, error) {
	return projectmeta.PublicMetadata{Namespace: "db.example", Services: map[string]projectmeta.Service{"database": {Protocol: "postgres", Namespace: "example", Hostname: "db.example", Port: 15432, Public: true}}}, b.deadline, b.startError
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
	n := b.credential.Add(1)
	return Connection{Schema: 1, Protocol: "postgres", Host: "db.example", Port: 15432, ExpiresAt: b.deadline, SSL: &TLSOptions{ServerName: "db.example", RejectUnauthorized: true, Cert: strings.Repeat("c", int(n)), Key: "private-snapshot"}}, nil
}
func (b *fixtureBackend) Renew(context.Context) (time.Time, error) { return b.deadline, nil }
func (b *fixtureBackend) Close(context.Context) error              { b.closed.Store(true); return nil }
func (b *fixtureBackend) Done() <-chan error                       { return b.failed }

func fixtureScope(t *testing.T) Context {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return Context{Schema: 1, Directory: root, ConfigDigest: strings.Repeat("a", 64), Server: "https://control.example", Audience: "https://control.example", ProjectKey: "project-test", SourceID: "source-test", WorktreeKey: "worktree-test", Services: []string{"database"}}
}
func TestConnectionOwnerPrivateSnapshotsAndJoinedStop(t *testing.T) {
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
		if err := Call(t.Context(), state.PrivateHandle, "connect", request, &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.SSL == nil || len(snapshot.SSL.Cert) != i {
			t.Fatal("credential snapshot was cached")
		}
	}
	wrong := request
	wrong.Directory += "-other"
	if err := Call(t.Context(), state.PrivateHandle, "connect", wrong, new(Connection)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("project scope: %v", err)
	}
	if err := Call(t.Context(), state.PrivateHandle, "stop", request, nil); err != nil {
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
	if _, err := os.Stat(state.PrivateHandle); !errors.Is(err, os.ErrNotExist) {
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
	go func() { requestDone <- Call(t.Context(), state.PrivateHandle, "connect", request, new(Connection)) }()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("credential did not start")
	}
	if err := Call(t.Context(), state.PrivateHandle, "stop", request, nil); err != nil {
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
	h, err := ReadHandle(state.PrivateHandle)
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
	if err := Call(t.Context(), state.PrivateHandle, "stop", Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}, nil); err != nil {
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
	if err := ReadStopResult(state.PrivateHandle); err != nil {
		t.Fatal(err)
	}
}
