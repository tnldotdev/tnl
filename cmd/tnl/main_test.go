package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestVersionCommand(t *testing.T) {
	var output, errors bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &output, &errors); err != nil {
		t.Fatal(err)
	}
	if output.String() != "tnl devel\n" || errors.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", output.String(), errors.String())
	}
}

func TestPublicNameOption(t *testing.T) {
	t.Setenv("TNL_NAME", "env-name")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"public", "3000", "--name", "flag-name"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "public <target>" || flags.Public.Name != "flag-name" {
		t.Fatalf("command = %q, name = %q", parsed.Command(), flags.Public.Name)
	}

	var envFlags cli
	envParser, err := kong.New(&envFlags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envParser.Parse([]string{"public", "3000"}); err != nil {
		t.Fatal(err)
	}
	if envFlags.Public.Name != "env-name" {
		t.Fatalf("environment name = %q", envFlags.Public.Name)
	}
}

func TestClaimAndPublicationNameResolution(t *testing.T) {
	kind, name, err := classifyClaimName("com", "tnl.dev")
	if err != nil || kind != serverv1.CreateHostnameClaimRequestKindPersistentManaged || name != "com" {
		t.Fatalf("managed com = %q, %q, %v", kind, name, err)
	}
	if _, _, err := classifyClaimName("com.", "tnl.dev"); err == nil {
		t.Fatal("absolute public suffix accepted")
	}
	if _, _, err := classifyClaimName("api.chase.tnl.dev", "tnl.dev"); err == nil {
		t.Fatal("managed descendant accepted as a base")
	}

	managed := serverv1.HostnameClaim{
		Id: "claim_00000000000000000000000000000001", Hostname: "com.tnl.dev",
		Kind: serverv1.HostnameClaimKindPersistentManaged, State: serverv1.HostnameClaimStateActive,
	}
	custom := serverv1.HostnameClaim{
		Id: "claim_00000000000000000000000000000002", Hostname: "example.com",
		Kind: serverv1.HostnameClaimKindPersistentCustomDomain, State: serverv1.HostnameClaimStateActive,
	}
	hostname, base, isManaged, implicit, err := resolvePublicationName("example.com", "tnl.dev", 8, []serverv1.HostnameClaim{managed})
	if err != nil || hostname != "example.com.tnl.dev" || base != "com.tnl.dev" || !isManaged || implicit {
		t.Fatalf("relative managed = %q, %q, %v, %v, %v", hostname, base, isManaged, implicit, err)
	}
	hostname, base, isManaged, _, err = resolvePublicationName("example.com", "tnl.dev", 8, []serverv1.HostnameClaim{managed, custom})
	if err != nil || hostname != "example.com" || base != "example.com" || isManaged {
		t.Fatalf("owned custom precedence = %q, %q, %v, %v", hostname, base, isManaged, err)
	}
	hostname, base, isManaged, _, err = resolvePublicationName("example.com.tnl.dev", "tnl.dev", 8, []serverv1.HostnameClaim{managed, custom})
	if err != nil || hostname != "example.com.tnl.dev" || base != "com.tnl.dev" || !isManaged {
		t.Fatalf("canonical managed = %q, %q, %v, %v", hostname, base, isManaged, err)
	}
	hostname, _, isManaged, _, err = resolvePublicationName("example.com.", "tnl.dev", 8, []serverv1.HostnameClaim{custom})
	if err != nil || hostname != "example.com" || isManaged {
		t.Fatalf("absolute custom = %q, %v, %v", hostname, isManaged, err)
	}
	if _, _, _, _, err := resolvePublicationName("a.b.c.d.e.f.g.h.i.com", "tnl.dev", 8, []serverv1.HostnameClaim{managed}); err == nil {
		t.Fatal("ninth-level managed descendant accepted")
	}
}

func TestReadLoginToken(t *testing.T) {
	token, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := readLoginToken(strings.NewReader(token.String()+"\n"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != token {
		t.Fatalf("token = %q", parsed)
	}
	if _, err := readLoginToken(strings.NewReader("invalid"), io.Discard); err == nil {
		t.Fatal("invalid token accepted")
	}
}

func TestClaimPublicHostnameAllocatesFreshEphemeralName(t *testing.T) {
	var requestKeys []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/hostname-claims" {
			http.NotFound(response, request)
			return
		}
		var body serverv1.CreateHostnameClaimRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Name != nil || body.Kind != serverv1.CreateHostnameClaimRequestKindEphemeral {
			t.Errorf("ephemeral claim request = %#v", body)
		}
		requestKeys = append(requestKeys, request.Header.Get("Idempotency-Key"))
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(serverv1.HostnameClaim{
			Id: "claim_0123456789abcdef0123456789abcdef", Hostname: "random.example",
			Kind: serverv1.HostnameClaimKindEphemeral, State: serverv1.HostnameClaimStateHeld,
			Source: serverv1.Generated, CreatedAt: time.Now(),
		})
	}))
	defer server.Close()
	client, err := serverclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		hostname, err := claimPublicHostname(
			context.Background(), client, "", serverv1.Capabilities{RouteSuffix: "example", MaximumChildDepth: 8},
		)
		if err != nil {
			t.Fatal(err)
		}
		if hostname != "random.example" {
			t.Fatalf("hostname = %q", hostname)
		}
	}
	if len(requestKeys) != 2 || requestKeys[0] == "" || requestKeys[1] == "" || requestKeys[0] == requestKeys[1] {
		t.Fatalf("request keys = %#v", requestKeys)
	}
}

func TestRunPublicPreflightsBeforeServerRequests(t *testing.T) {
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
		Target: target, ServerURL: server.URL, AccessToken: "invalid", Output: "ndjson",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runPublic accepted an offline target")
	}
	if requests.Load() != 0 {
		t.Fatalf("server requests = %d", requests.Load())
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
		case request.Method == http.MethodGet && request.URL.Path == "/v1/capabilities":
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(testNamingCapabilities())
		case request.Method == http.MethodGet && request.URL.Path == "/v1/hostname-claims":
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(serverv1.HostnameClaimPage{Claims: []serverv1.HostnameClaim{{
				Id: "claim_0123456789abcdef0123456789abcdef", Hostname: "random.example",
				Kind: serverv1.HostnameClaimKindPersistentManaged, State: serverv1.HostnameClaimStateActive,
				Source: serverv1.Custom, CreatedAt: time.Now(),
			}}})
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/hostname-claims/claim_0123456789abcdef0123456789abcdef":
			if deleted.Load() {
				response.Header().Set("Content-Type", "application/problem+json")
				response.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(response).Encode(serverv1.Problem{Code: serverv1.NotFound})
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
	var output bytes.Buffer
	flags := hostReleaseCommand{
		Hostname: "random.example", ServerURL: server.URL, AccessToken: access.String(), StateDir: filepath.Join(t.TempDir(), "state"),
	}
	if err := runHostRelease(context.Background(), flags, &output); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("ambiguous release error = %v", err)
	}
	if err := runHostRelease(context.Background(), flags, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "random.example\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestHostListWithExplicitTokenDoesNotOpenClientState(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/capabilities" {
			_ = json.NewEncoder(response).Encode(testNamingCapabilities())
			return
		}
		if request.URL.Path != "/v1/hostname-claims" || request.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Errorf("request = %s %s authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(response).Encode(serverv1.HostnameClaimPage{})
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
		ServerURL: server.URL, AccessToken: access.String(), StateDir: statePath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func testNamingCapabilities() serverv1.Capabilities {
	return serverv1.Capabilities{
		RouteSuffix: "example", MaximumChildDepth: 8, CustomDomainSupport: true,
		IngressIpv4: []string{}, IngressIpv6: []string{},
		ProtocolVersions:      []serverv1.CapabilitiesProtocolVersions{serverv1.CapabilitiesProtocolVersionsN1},
		HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalClaim},
		NameAuthorityType:     serverv1.Local,
		Transport: serverv1.TransportCapabilities{
			Type: serverv1.Tailcat, Version: serverv1.TransportCapabilitiesVersionN1, RelayProfile: "default",
		},
	}
}
