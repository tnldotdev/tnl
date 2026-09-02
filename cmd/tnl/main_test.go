package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/tnldotdev/tnl/internal/state"
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

func TestAdminCommandTree(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	commands := map[string]bool{}
	for _, command := range parser.Model.Leaves(true) {
		commands[command.Path()] = true
	}
	for _, command := range []string{
		"admin server status", "admin server login-token", "admin server token worker",
		"admin server token service", "admin server relay refresh", "admin routes list",
		"admin routes show", "admin routes suspend", "admin routes resume", "admin hostnames list",
		"admin hostnames show", "admin hostnames remove", "admin hostnames quarantine",
		"admin credentials list", "admin credentials revoke", "admin control-sessions list",
		"admin control-sessions revoke", "admin switches list", "admin switches enable", "admin switches disable",
	} {
		if !commands[command] {
			t.Fatalf("command %q missing from help model", command)
		}
	}
}

func TestAdminServerTokenCommands(t *testing.T) {
	for _, tokenType := range []string{"worker", "service"} {
		t.Run(tokenType, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(t.Context(), []string{"admin", "server", "token", tokenType}, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			value := strings.TrimSpace(stdout.String())
			var err error
			if tokenType == "worker" {
				_, err = credentials.ParseWorkerToken(credentials.WorkerToken(value))
			} else {
				_, err = credentials.ParseServiceToken(credentials.ServiceToken(value))
			}
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("parse token: %v; stderr = %q", err, stderr.String())
			}
		})
	}
}

func TestAdminServerLoginTokenRequiresLockForRotation(t *testing.T) {
	directory := t.TempDir()
	lock, err := state.LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := state.EnsureLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"admin", "server", "login-token", "--state-dir", directory}
	if err := run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != token.String() {
		t.Fatalf("login token = %q", got)
	}
	if err := run(t.Context(), append(args, "--rotate"), &stdout, &stderr); !errors.Is(err, state.ErrLocked) {
		t.Fatalf("rotation error = %v, want locked", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run(t.Context(), append(args, "--rotate"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got == token.String() {
		t.Fatal("rotation returned the previous login token")
	}
}

func TestPublishNameOption(t *testing.T) {
	t.Setenv("TNL_NAME", "env-name")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"publish", "3000", "--name", "flag-name"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "publish <target>" || flags.Publish.Name != "flag-name" {
		t.Fatalf("command = %q, name = %q", parsed.Command(), flags.Publish.Name)
	}

	var envFlags cli
	envParser, err := kong.New(&envFlags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envParser.Parse([]string{"publish", "3000"}); err != nil {
		t.Fatal(err)
	}
	if envFlags.Publish.Name != "env-name" {
		t.Fatalf("environment name = %q", envFlags.Publish.Name)
	}
}

func TestPublishIPAllowlistOptions(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{
		"publish", "3000", "--allow-ip", "192.0.2.1", "--allow-ip=2001:db8::/64", "--allow-current-ip",
	}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(flags.Publish.AllowIP) != "[192.0.2.1 2001:db8::/64]" || !flags.Publish.AllowCurrentIP {
		t.Fatalf("publish allowlist flags = %#v", flags.Publish)
	}
}

func TestHostnameAndPublishNameResolution(t *testing.T) {
	kind, name, err := classifyAddHostname("com", "tnl.dev")
	if err != nil || kind != serverv1.AddHostnameRequestKindManaged || name != "com" {
		t.Fatalf("managed com = %q, %q, %v", kind, name, err)
	}
	if _, _, err := classifyAddHostname("com.", "tnl.dev"); err == nil {
		t.Fatal("absolute public suffix accepted")
	}
	if _, _, err := classifyAddHostname("api.chase.tnl.dev", "tnl.dev"); err == nil {
		t.Fatal("managed descendant accepted as a base")
	}

	managed := serverv1.Hostname{
		Id: "hostname_00000000000000000000000000000001", Hostname: "com.tnl.dev",
		Kind: serverv1.HostnameKindManaged, Status: serverv1.HostnameStatusActive,
	}
	custom := serverv1.Hostname{
		Id: "hostname_00000000000000000000000000000002", Hostname: "example.com",
		Kind: serverv1.HostnameKindCustomDomain, Status: serverv1.HostnameStatusActive,
	}
	hostname, base, isManaged, implicit, err := resolvePublishName("example.com", "tnl.dev", 8, []serverv1.Hostname{managed})
	if err != nil || hostname != "example.com.tnl.dev" || base != "com.tnl.dev" || !isManaged || implicit {
		t.Fatalf("relative managed = %q, %q, %v, %v, %v", hostname, base, isManaged, implicit, err)
	}
	hostname, base, isManaged, _, err = resolvePublishName("example.com", "tnl.dev", 8, []serverv1.Hostname{managed, custom})
	if err != nil || hostname != "example.com" || base != "example.com" || isManaged {
		t.Fatalf("owned custom precedence = %q, %q, %v, %v", hostname, base, isManaged, err)
	}
	hostname, base, isManaged, _, err = resolvePublishName("example.com.tnl.dev", "tnl.dev", 8, []serverv1.Hostname{managed, custom})
	if err != nil || hostname != "example.com.tnl.dev" || base != "com.tnl.dev" || !isManaged {
		t.Fatalf("canonical managed = %q, %q, %v, %v", hostname, base, isManaged, err)
	}
	hostname, _, isManaged, _, err = resolvePublishName("example.com.", "tnl.dev", 8, []serverv1.Hostname{custom})
	if err != nil || hostname != "example.com" || isManaged {
		t.Fatalf("absolute custom = %q, %v, %v", hostname, isManaged, err)
	}
	if _, _, _, _, err := resolvePublishName("a.b.c.d.e.f.g.h.i.com", "tnl.dev", 8, []serverv1.Hostname{managed}); err == nil {
		t.Fatal("ninth-level managed descendant accepted")
	}
}

func TestReadLoginToken(t *testing.T) {
	token, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseLoginInput([]byte(token.String() + "\n"))
	if err != nil || parsed != token {
		t.Fatalf("token = %q, error = %v", parsed, err)
	}
	if _, err := parseLoginInput([]byte("invalid")); err == nil {
		t.Fatal("invalid token accepted")
	}
	if _, err := readLoginToken(strings.NewReader(token.String()), &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("noninteractive login-token error = %v", err)
	}
}

func TestAddTemporaryHostnameAllocatesFreshName(t *testing.T) {
	var requestKeys []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/hostnames" {
			http.NotFound(response, request)
			return
		}
		var body serverv1.AddHostnameRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Name != nil || body.Kind != serverv1.AddHostnameRequestKindTemporary {
			t.Errorf("temporary hostname request = %#v", body)
		}
		requestKeys = append(requestKeys, request.Header.Get("Idempotency-Key"))
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(serverv1.Hostname{
			Id: "hostname_0123456789abcdef0123456789abcdef", Hostname: "random.example",
			Kind: serverv1.HostnameKindTemporary, Status: serverv1.HostnameStatusPendingRoute,
			Source: serverv1.Generated, CreatedAt: time.Now(),
		})
	}))
	defer server.Close()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	client, err := serverclient.New(server.URL, server.Client(), access)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		hostname, err := addPublishHostname(
			context.Background(), client, "", serverv1.Capabilities{HostnameSuffix: "example", MaximumSubdomainDepth: 8},
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

func TestRunPublishPreflightsBeforeServerRequests(t *testing.T) {
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
	err = runPublish(context.Background(), publishCommand{
		Target: target, ServerURL: server.URL, AccessToken: "invalid", Output: "ndjson",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runPublish accepted an offline target")
	}
	if requests.Load() != 0 {
		t.Fatalf("server requests = %d", requests.Load())
	}
	var starting, failed publishEvent
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

func TestRunPublishReadsCurrentIPAfterAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.Path)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/capabilities":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("capabilities authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(testNamingCapabilities())
		case "/v1/client-ip":
			if request.Header.Get("Authorization") != "Bearer "+access.String() {
				t.Errorf("client IP authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(response).Encode(serverv1.ClientIPResponse{Ip: "invalid"})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	var stdout, stderr bytes.Buffer
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	err = runPublish(t.Context(), publishCommand{
		Target: port, ServerURL: server.URL, AccessToken: access.String(),
		StateDir: t.TempDir(), Output: "ndjson", AllowCurrentIP: true,
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "invalid current IP") {
		t.Fatalf("runPublish error = %v", err)
	}
	if fmt.Sprint(requests) != "[/v1/capabilities /v1/client-ip]" {
		t.Fatalf("request order = %v", requests)
	}
}

func TestRunPublishNDJSONReportsInvalidTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runPublish(context.Background(), publishCommand{Target: "example.com:3000", Output: "ndjson"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runPublish accepted an invalid target")
	}
	var event publishEvent
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "error" || event.Cursor != 1 || event.Message == "" {
		t.Fatalf("event = %#v", event)
	}
}

func TestRunPublishNDJSONStopsOnEarlyCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	err = runPublish(ctx, publishCommand{
		Target: listener.Addr().String()[strings.LastIndex(listener.Addr().String(), ":")+1:], Output: "ndjson",
	}, &stdout, &stderr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runPublish error = %v", err)
	}
	decoder := json.NewDecoder(&stdout)
	for _, want := range []string{"starting", "stopped"} {
		var event publishEvent
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
		case request.Method == http.MethodGet && request.URL.Path == "/v1/hostnames":
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(serverv1.HostnamePage{Hostnames: []serverv1.Hostname{{
				Id: "hostname_0123456789abcdef0123456789abcdef", Hostname: "random.example",
				Kind: serverv1.HostnameKindManaged, Status: serverv1.HostnameStatusActive,
				Source: serverv1.User, CreatedAt: time.Now(),
			}}})
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/hostnames/hostname_0123456789abcdef0123456789abcdef":
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
	flags := hostRemoveCommand{
		Hostname: "random.example", ServerURL: server.URL, AccessToken: access.String(), StateDir: filepath.Join(t.TempDir(), "state"),
	}
	if err := runHostRemove(context.Background(), flags, &output); !errors.Is(err, serverclient.ErrUnavailable) {
		t.Fatalf("ambiguous release error = %v", err)
	}
	if err := runHostRemove(context.Background(), flags, &output); err != nil {
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
		if request.URL.Path != "/v1/hostnames" || request.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Errorf("request = %s %s authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(response).Encode(serverv1.HostnamePage{Hostnames: []serverv1.Hostname{{
			Id: "hostname_0123456789abcdef0123456789abcdef", Hostname: "random.example",
			Kind: serverv1.HostnameKindTemporary, Status: serverv1.HostnameStatusPendingRoute,
		}}})
	}))
	defer server.Close()
	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runHostList(context.Background(), hostListCommand{
		ServerURL: server.URL, AccessToken: access.String(), StateDir: statePath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "NAME\tTYPE\tSTATE\nrandom.example\ttemporary\tpending_route\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestResolveReleaseNameRejectsTemporaryHostname(t *testing.T) {
	_, _, err := resolveReleaseName("random", "example", []serverv1.Hostname{{
		Id: "hostname_0123456789abcdef0123456789abcdef", Hostname: "random.example",
		Kind: serverv1.HostnameKindTemporary, Status: serverv1.HostnameStatusActive,
	}})
	if err == nil || err.Error() != "temporary hostnames are retired with their route and cannot be removed" {
		t.Fatalf("error = %v", err)
	}
}

func testNamingCapabilities() serverv1.Capabilities {
	return serverv1.Capabilities{
		HostnameSuffix: "example", MaximumSubdomainDepth: 8, CustomDomainSupport: true,
		IngressIpv4: []string{}, IngressIpv6: []string{},
		ProtocolVersions: []serverv1.CapabilitiesProtocolVersions{serverv1.CapabilitiesProtocolVersionsN1},
		Authentication: serverv1.AuthenticationCapabilities{
			Required: serverv1.True, Methods: []serverv1.AuthenticationCapabilitiesMethods{serverv1.LoginToken},
		},
		HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalHostnames},
		Transport: serverv1.TransportCapabilities{
			Type: serverv1.Tailcat, Version: serverv1.TransportCapabilitiesVersionN1, RelayRegion: "default",
		},
	}
}
