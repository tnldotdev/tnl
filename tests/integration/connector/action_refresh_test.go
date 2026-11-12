package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorworkload "github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// the action returns after startup. only its explicit private job-runtime source
// may outlive that call; SDK callbacks and static assertions remain finite.
func TestIntegrationConnectionConnectorOwnerActionBackgroundRefresh(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "tnl")
	build := exec.CommandContext(t.Context(), "go", "build", "-race", "-o", binary, "./cmd/tnl")
	build.Dir = "../../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native build: %v %s", err, output)
	}
	for _, source := range []string{"fresh", "unavailable", "stalled", "redirect", "replacement-job", "static", "wrong-audience", "wrong-provider"} {
		t.Run(source, func(t *testing.T) {
			runConnectionNativeOwnerBinary(t, "http", true, "action-"+source, binary)
		})
	}
}

func rejectMismatchedActionRefresh(t *testing.T, binary string, env, args []string, input []byte, root string, proofs func() []string) {
	t.Helper()
	rejectActionStartup(t, binary, env, args, input, root, proofs, failure.ConnectionRequestInvalid)
}

func rejectActionStartup(t *testing.T, binary string, env, args []string, input []byte, root string, proofs func() []string, reason failure.Reason) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append([]string{"--no-telemetry", "runtime", "connections"}, args...)...)
	command.Env, command.Stdin = env, bytes.NewReader(input)
	var output, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostics
	err := command.Run()
	assertActionSourcePrivate(t, root, proofs(), []byte(strings.Join(command.Args, "\x00")), output.Bytes(), diagnostics.Bytes())
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) {
		t.Fatal("Action startup did not reject normally within its original budget")
	}
	if len(bytes.TrimSpace(output.Bytes())) != 0 {
		t.Fatal("rejected Action startup published an owner status")
	}
	var problem struct {
		Reason failure.Reason `json:"reason"`
	}
	if json.Unmarshal(diagnostics.Bytes(), &problem) != nil || problem.Reason == "" || reason != "" && problem.Reason != reason {
		t.Fatal("Action startup rejection did not retain its structured failure reason")
	}
}

type actionProviderDenial struct {
	status           int
	request          authorityv1.EnvironmentVisitorPrepareRequest
	providerMismatch bool
}

func assertActionProviderDenial(t *testing.T, denial actionProviderDenial, start connectorruntime.EnvironmentStart, assertion string) {
	t.Helper()
	request := denial.request
	if denial.status != http.StatusForbidden || !denial.providerMismatch || request.Assertion != assertion || request.PermissionId != start.Selection.PermissionID || !workloadproof.ValidNonce(request.Nonce) || len(request.Services) != len(start.Selection.Services) {
		t.Fatal("canonical Prepare did not reject the exact valid source proof with HTTP 403 provider-policy denial")
	}
	services := make(map[string]string, len(request.Services))
	for name, protocol := range request.Services {
		services[name] = string(protocol)
		if services[name] != start.Selection.Services[name] {
			t.Fatal("provider-policy denial used another service selection")
		}
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(request.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(request.Signature)
	if err != nil || signatureErr != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, machineproof.EnvironmentVisitorPossession(start.Selection.Environment.ProjectKey, start.Selection.PermissionID, start.Selection.Environment.EnvironmentId, "prepare", request.PublicKey, request.Nonce, services, sha256.Sum256([]byte(assertion))), signature) {
		t.Fatal("provider-policy denial did not traverse a valid native key possession request")
	}
}

func assertRejectedActionHasNoOwner(t *testing.T, root string, port int) {
	t.Helper()
	handles, err := filepath.Glob(filepath.Join(root, "tnl-connections-*", "handle.json"))
	if err != nil || len(handles) != 0 {
		t.Fatal("rejected Action startup retained a native owner capability", err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal("rejected Action startup left its selected service listener bound", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertActionSourcePrivate(t *testing.T, root string, proofs []string, observations ...[]byte) {
	t.Helper()
	private := [][]byte{[]byte("action-private-runtime-bearer"), []byte("/action-provider-token")}
	for _, proof := range proofs {
		private = append(private, []byte(proof))
	}
	check := func(data []byte) {
		t.Helper()
		for _, secret := range private {
			if bytes.Contains(data, secret) {
				t.Fatal("job-runtime refresh credentials escaped private startup")
			}
		}
	}
	for _, observation := range observations {
		check(observation)
	}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil {
			check(data)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type actionRefreshFixture struct {
	root, mode                              string
	state                                   connectorruntime.Status
	prepared                                connectorruntime.Prepared
	roots                                   *x509.CertPool
	expiry                                  time.Time
	providerCalls, redirectedCalls, streams *atomic.Int32
	refreshed, providerCanceled             <-chan struct{}
	release                                 chan struct{}
	call                                    func([]byte, ...string) []byte
	inspect                                 func() (map[string]int, fixtureVisitorSession, int)
	privateProofs                           func() []string
}

func qualifyActionBackgroundRefresh(t *testing.T, f actionRefreshFixture) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() || f.mode == "action-fresh" {
			return
		}
		data, readErr := os.ReadFile(filepath.Join(filepath.Dir(f.state.ConnectionHandle), "stopped.json"))
		var stopped struct {
			Schema int  `json:"schema"`
			Clean  bool `json:"clean"`
		}
		decodeErr := json.Unmarshal(data, &stopped)
		calls, _, _ := f.inspect()
		t.Logf("expired-owner cleanup: record=%t decoded=%t schema=%d clean=%t revoke_calls=%d", readErr == nil, decodeErr == nil, stopped.Schema, stopped.Clean, calls["DELETE /v1/environment-visitor-sessions/{session}"])
	})
	_, original, _ := f.inspect()
	first := f.prepared.Connection
	if !original.IdentityExpiresAt.Equal(f.expiry) || first.ExpiresAt.After(f.expiry) {
		t.Fatal("startup did not retain the initial finite proof boundary")
	}
	initialHandle, err := connectorruntime.ReadHandle(f.state.ConnectionHandle)
	if err != nil || !initialHandle.ExpiresAt.Equal(f.state.ExpiresAt) || !initialHandle.ExpiresAt.Equal(connectorworkload.SessionDeadline(original.EnvironmentVisitorSession)) {
		t.Fatal("startup handle did not retain the accepted proof and optional hard deadline", err)
	}
	argv, err := exec.CommandContext(t.Context(), "ps", "-p", strconv.Itoa(f.state.PID), "-o", "command=").Output()
	if err != nil {
		t.Fatal("could not inspect detached owner arguments", err)
	}
	// the starter has exited and the checkout was removed by the shared fixture.
	// no later caller supplies another assertion or invokes preparation/attach.
	ctx, cancel := context.WithDeadline(t.Context(), f.expiry.Add(5*time.Second))
	defer cancel()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots, ServerName: first.SSL.ServerName}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(first.Host, strconv.Itoa(first.Port)))
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, first.URL+"/refresh-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal("Action stream did not open before the initial proof expired", err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "before-proof\n" {
		t.Fatal("Action stream did not reach the quiet interval", err)
	}
	type readResult struct {
		line string
		err  error
	}
	result := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		result <- readResult{line, err}
	}()
	if f.mode == "action-fresh" {
		timer := time.NewTimer(time.Until(f.expiry))
		defer timer.Stop()
		select {
		case <-f.refreshed:
		case <-timer.C:
			t.Fatal("quiet Action owner did not acquire and attach a fresh signed GitHub proof before expiry")
		}
	}
	timer := time.NewTimer(time.Until(f.expiry.Add(time.Second)))
	defer timer.Stop()
	<-timer.C
	if f.mode == "action-fresh" {
		close(f.release)
		select {
		case read := <-result:
			if read.err != nil || read.line != "after-proof\n" {
				t.Fatal("original Action stream did not survive proof expiry", read.err)
			}
		case <-ctx.Done():
			t.Fatal("original Action stream stalled after refresh")
		}
		var after connectorruntime.Prepared
		if err := json.Unmarshal(f.call(nil, "read", "--handle", f.state.ConnectionHandle, "--service", "api"), &after); err != nil {
			t.Fatal(err)
		}
		var state connectorruntime.Status
		if err := json.Unmarshal(f.call(nil, "status", "--handle", f.state.ConnectionHandle), &state); err != nil {
			t.Fatal(err)
		}
		calls, current, keys := f.inspect()
		if state.PID != f.state.PID || state.ConnectionHandle != f.state.ConnectionHandle || first.TransportID != after.Connection.TransportID || first.Host != after.Connection.Host || first.Port != after.Connection.Port || !after.Connection.ExpiresAt.After(first.ExpiresAt) || f.streams.Load() != 1 {
			t.Fatal("refresh replaced the Action owner, listener, transport or original stream")
		}
		afterHandle, err := connectorruntime.ReadHandle(f.state.ConnectionHandle)
		expectedHandle := initialHandle
		expectedHandle.ExpiresAt = afterHandle.ExpiresAt
		if err != nil || expectedHandle != afterHandle || !afterHandle.ExpiresAt.Equal(state.ExpiresAt) {
			t.Fatal("refresh replaced or failed to publish the exact local capability", err)
		}
		if current.Id != original.Id || current.Credential != original.Credential || current.execution.IdentityDigest() != original.execution.IdentityDigest() || !reflect.DeepEqual(current.execution.GitHub, original.execution.GitHub) || !reflect.DeepEqual(current.public, original.public) || current.nonce != original.nonce || current.permission != original.permission || current.machine != original.machine || current.environment != original.environment || !reflect.DeepEqual(current.services, original.services) || !reflect.DeepEqual(current.ServiceIds, original.ServiceIds) || !reflect.DeepEqual(current.Subject, original.Subject) || !reflect.DeepEqual(current.ExpiresAt, original.ExpiresAt) || !current.IdentityExpiresAt.After(original.IdentityExpiresAt) || keys != 1 || calls["POST /v1/projects/connector-fixture/environments/{environment}/visitors/prepare"] != 2 || calls["POST /v1/environment-visitor-sessions/{session}/assertions"] != 1 || f.providerCalls.Load() != 2 {
			t.Fatal("refresh replaced identity, broadened rights or repeated exchange instead of attaching one fresh proof")
		}
		// the owner handle follows accepted proof, bounded by the optional hard
		// deadline. prepared connections also retain their shorter permission lease.
		accepted := connectorworkload.SessionDeadline(current.EnvironmentVisitorSession)
		if !state.ExpiresAt.After(f.state.ExpiresAt) || !state.ExpiresAt.Equal(accepted) {
			t.Fatalf("local expiry did not advance to accepted authority: before=%s after=%s accepted=%s", f.state.ExpiresAt.Format(time.RFC3339Nano), state.ExpiresAt.Format(time.RFC3339Nano), accepted.Format(time.RFC3339Nano))
		}
		if state.ExpiresAt.After(current.IdentityExpiresAt) || current.LeaseExpiresAt.After(current.IdentityExpiresAt) || after.Connection.ExpiresAt.After(current.LeaseExpiresAt) || after.Connection.ExpiresAt.After(current.IdentityExpiresAt) || current.ExpiresAt != nil && (state.ExpiresAt.After(*current.ExpiresAt) || current.LeaseExpiresAt.After(*current.ExpiresAt) || after.Connection.ExpiresAt.After(*current.ExpiresAt)) {
			t.Fatal("refresh relaxed a proof, lease or fixed session expiry")
		}
		t.Logf("Action expiry: handle before=%s after=%s; connection=%s lease=%s proof=%s", f.state.ExpiresAt.Format(time.RFC3339Nano), state.ExpiresAt.Format(time.RFC3339Nano), after.Connection.ExpiresAt.Format(time.RFC3339Nano), current.LeaseExpiresAt.Format(time.RFC3339Nano), current.IdentityExpiresAt.Format(time.RFC3339Nano))
	} else {
		select {
		case read := <-result:
			if read.err == nil || read.line != "" {
				t.Fatal("failed refresh left its original stream usable past accepted proof expiry")
			}
		default:
			t.Fatal("failed refresh did not close the quiet stream at accepted proof expiry")
		}
		calls, current, keys := f.inspect()
		if !current.IdentityExpiresAt.Equal(original.IdentityExpiresAt) || current.LeaseExpiresAt.After(f.expiry) || !reflect.DeepEqual(current.ExpiresAt, original.ExpiresAt) || current.Id != original.Id || current.execution.IdentityDigest() != original.execution.IdentityDigest() || !reflect.DeepEqual(current.execution.GitHub, original.execution.GitHub) || !reflect.DeepEqual(current.public, original.public) || current.nonce != original.nonce || current.permission != original.permission || current.machine != original.machine || current.environment != original.environment || !reflect.DeepEqual(current.services, original.services) || keys != 1 || calls["POST /v1/projects/connector-fixture/environments/{environment}/visitors/prepare"] != 2 {
			t.Fatal("failed refresh extended accepted authority or replaced the original job")
		}
		if f.mode == "action-static" {
			if f.providerCalls.Load() != 0 {
				t.Fatal("static startup implicitly became a job-runtime refresh source")
			}
		} else if f.providerCalls.Load() == 0 {
			t.Fatal("explicit Action refresh source was never attempted")
		}
		attachments := calls["POST /v1/environment-visitor-sessions/{session}/assertions"]
		if (f.mode == "action-replacement-job") != (attachments > 0) {
			t.Fatal("replacement job was not checked, or unavailable proof reached attachment")
		}
		if f.mode == "action-stalled" {
			select {
			case <-f.providerCanceled:
			default:
				t.Fatal("body progress let refresh acquisition outlive accepted proof expiry")
			}
		}
		before := f.providerCalls.Load()
		time.Sleep(150 * time.Millisecond)
		if f.providerCalls.Load() != before {
			t.Fatal("acquisition continued after accepted proof expiry")
		}
	}
	if f.redirectedCalls.Load() != 0 {
		t.Fatal("job-runtime refresh followed a redirect with its request bearer")
	}
	// inspect descriptors and argv without ever printing their private contents.
	private := [][]byte{[]byte("action-private-runtime-bearer"), []byte("/action-provider-token")}
	for _, proof := range f.privateProofs() {
		private = append(private, []byte(proof))
	}
	check := func(data []byte) {
		t.Helper()
		for _, secret := range private {
			if bytes.Contains(data, secret) {
				t.Fatal("job-runtime refresh credentials escaped private in-memory startup")
			}
		}
	}
	check(argv)
	if err := filepath.WalkDir(f.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil {
			check(data)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
