package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
)

func TestTokenCommands(t *testing.T) {
	for _, test := range []struct {
		name  string
		args  []string
		parse func(string) error
	}{
		{name: "bootstrap", args: []string{"token", "bootstrap"}, parse: func(value string) error {
			_, err := credentials.ParseBootstrapToken(credentials.BootstrapToken(value))
			return err
		}},
		{name: "worker", args: []string{"token", "worker"}, parse: func(value string) error {
			_, err := credentials.ParseWorkerToken(credentials.WorkerToken(value))
			return err
		}},
		{name: "workload", args: []string{"token", "workload"}, parse: func(value string) error {
			_, err := credentials.ParseWorkloadToken(credentials.WorkloadToken(value))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output, errors bytes.Buffer
			if err := run(context.Background(), test.args, &output, &errors); err != nil {
				t.Fatal(err)
			}
			if err := test.parse(strings.TrimSpace(output.String())); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	var output, errors bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	if output.String() != "tnl devel\n" || errors.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", output.String(), errors.String())
	}
}

func TestClaimPublicHostnamePersistsRandomSelection(t *testing.T) {
	var requestKeys []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/hostname-claims" {
			http.NotFound(response, request)
			return
		}
		var body corev1.CreateHostnameClaimRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Label != nil {
			t.Errorf("random claim label = %q", *body.Label)
		}
		requestKeys = append(requestKeys, request.Header.Get("Idempotency-Key"))
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(corev1.HostnameClaim{
			Id: "claim_0123456789abcdef0123456789abcdef", Hostname: "random.example", CreatedAt: time.Now(),
		})
	}))
	defer server.Close()
	client, err := coreclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	state, err := clientstate.New(filepath.Join(t.TempDir(), "state"), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		hostname, err := claimPublicHostname(
			context.Background(), client, state, "http://127.0.0.1:3000", "", "example",
		)
		if err != nil {
			t.Fatal(err)
		}
		if hostname != "random.example" {
			t.Fatalf("hostname = %q", hostname)
		}
	}
	if len(requestKeys) != 2 || requestKeys[0] == "" || requestKeys[0] != requestKeys[1] {
		t.Fatalf("request keys = %#v", requestKeys)
	}
	selection, found, err := state.HostnameSelection("http://127.0.0.1:3000")
	if err != nil || !found || selection.Hostname != "random.example" || selection.ClaimID == "" {
		t.Fatalf("selection = %#v, found = %v, err = %v", selection, found, err)
	}
}

func TestRunPublicPreflightsBeforeCoreRequests(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	err = runPublic(context.Background(), publicCommand{
		Target: target, CoreURL: server.URL, AccessToken: "invalid", Output: "ndjson",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runPublic accepted an offline target")
	}
	if requests.Load() != 0 {
		t.Fatalf("core requests = %d", requests.Load())
	}
	var starting, failed publicEvent
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&starting); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&failed); err != nil {
		t.Fatal(err)
	}
	if starting.Type != "starting" || failed.Type != "error" {
		t.Fatalf("events = %#v, %#v", starting, failed)
	}
}

func TestRunPublicNDJSONReportsInvalidTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runPublic(context.Background(), publicCommand{Target: "localhost:3000", Output: "ndjson"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runPublic accepted an invalid target")
	}
	var event publicEvent
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "error" || event.Cursor != 1 || event.Message == "" {
		t.Fatalf("event = %#v", event)
	}
}

func TestRunPublicNDJSONStopsOnEarlyCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	err = runPublic(ctx, publicCommand{
		Target: listener.Addr().String()[strings.LastIndex(listener.Addr().String(), ":")+1:], Output: "ndjson",
	}, &stdout, &stderr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runPublic error = %v", err)
	}
	decoder := json.NewDecoder(&stdout)
	for _, want := range []string{"starting", "stopped"} {
		var event publicEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != want {
			t.Fatalf("event = %#v, want %q", event, want)
		}
	}
}

func TestHostReleaseRecoversAfterAmbiguousDelete(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var deleted atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/hostname-claims":
			response.Header().Set("Content-Type", "application/json")
			if deleted.Load() {
				_, _ = response.Write([]byte("[]"))
				return
			}
			_ = json.NewEncoder(response).Encode(corev1.HostnameClaimPage{Claims: []corev1.HostnameClaim{{
				Id: "claim_0123456789abcdef0123456789abcdef", Hostname: "random.example", CreatedAt: time.Now(),
			}}})
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/hostname-claims/claim_0123456789abcdef0123456789abcdef":
			if deleted.Load() {
				response.Header().Set("Content-Type", "application/problem+json")
				response.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(response).Encode(corev1.Problem{Code: corev1.NotFound})
				return
			}
			deleted.Store(true)
			connection, _, err := response.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close() // Simulate a committed delete whose response was lost.
		default:
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	stateRoot := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.New(stateRoot, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SaveHostnameSelection("http://127.0.0.1:3000", clientstate.HostnameSelection{
		RequestKey: "random_request", ClaimID: "claim_0123456789abcdef0123456789abcdef", Hostname: "random.example",
	}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	flags := hostReleaseCommand{
		Hostname: "random.example", CoreURL: server.URL, AccessToken: access.String(), StateDir: stateRoot,
	}
	if err := runHostRelease(context.Background(), flags, &output); !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("ambiguous release error = %v", err)
	}
	if claimID, found, err := state.PendingHostnameRelease("random.example"); err != nil || !found || claimID == "" {
		t.Fatalf("pending release = %q, found = %v, err = %v", claimID, found, err)
	}
	if err := runHostRelease(context.Background(), flags, failingWriter{}); err == nil {
		t.Fatal("release succeeded with a failed output write")
	}
	if claimID, found, err := state.PendingHostnameRelease("random.example"); err != nil || !found || claimID == "" {
		t.Fatalf("pending release after output failure = %q, found = %v, err = %v", claimID, found, err)
	}
	if err := runHostRelease(context.Background(), flags, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "random.example\n" {
		t.Fatalf("output = %q", output.String())
	}
	if selection, found, err := state.HostnameSelection("http://127.0.0.1:3000"); err != nil || found {
		t.Fatalf("selection = %#v, found = %v, err = %v", selection, found, err)
	}
	if claimID, found, err := state.PendingHostnameRelease("random.example"); err != nil || found {
		t.Fatalf("pending release = %q, found = %v, err = %v", claimID, found, err)
	}
}

func TestHostListWithExplicitTokenDoesNotOpenClientState(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(corev1.HostnameClaimPage{})
	}))
	defer server.Close()
	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runHostList(context.Background(), hostListCommand{
		CoreURL: server.URL, AccessToken: access.String(), StateDir: statePath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
