package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func validateFixtureChallenge(t *testing.T, challenge authorityv1.IdentitySourceChallenge, start connectorruntime.EnvironmentStart, operation authorityv1.IdentitySourceChallengeOperation) {
	t.Helper()
	selection := challenge.Selection
	if machineproof.ValidateSourceChallenge(challenge, time.Now()) != nil || challenge.Source != start.Source || challenge.Server != start.Selection.Environment.Server || challenge.Operation != operation || selection == nil || selection.Environment != start.Selection.Environment || selection.PermissionId != start.Selection.PermissionID || len(selection.Services) != len(start.Selection.Services) {
		t.Fatal("native source challenge changed the selected identity, environment or permission")
	}
	for name, protocol := range selection.Services {
		if string(protocol) != start.Selection.Services[name] {
			t.Fatal("native source challenge changed the expected service protocol")
		}
	}
}

func startFixtureEnvironment(t *testing.T, binary string, env []string, start connectorruntime.EnvironmentStart, assertion string) (connectorruntime.Status, string, func()) {
	t.Helper()
	lifetime, cancel := context.WithCancel(t.Context())
	command := exec.CommandContext(lifetime, binary, "--no-telemetry", "runtime", "connections", "environment-serve", "--parent-pid", strconv.Itoa(os.Getpid()))
	command.Env = env
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	wait := sync.OnceValue(command.Wait)
	var state connectorruntime.Status
	stopOwner := sync.OnceFunc(func() {
		defer cancel()
		ctx, finish := context.WithTimeout(context.Background(), 45*time.Second)
		defer finish()
		kill := context.AfterFunc(ctx, func() { _ = command.Process.Kill() })
		defer kill()
		if state.ConnectionHandle != "" {
			handle, err := connectorruntime.ReadHandle(state.ConnectionHandle)
			if err == nil {
				err = connectorruntime.Call(ctx, state.ConnectionHandle, "stop", connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest}, nil)
			}
			if err != nil {
				t.Errorf("canonical native owner stop failed: %v", err)
			}
		}
		_ = input.Close()
		if err := wait(); err != nil {
			t.Errorf("canonical native owner did not join cleanly: %v %s", err, diagnostics.Bytes())
		}
	})
	t.Cleanup(stopOwner)
	setup, finish := context.WithTimeout(lifetime, 45*time.Second)
	defer finish()
	stop := context.AfterFunc(setup, func() { _ = command.Process.Kill() })
	defer stop()
	if err := json.NewEncoder(input).Encode(start); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(output)
	lines.Buffer(make([]byte, 4096), connectorruntime.MaxBytes)
	if !lines.Scan() {
		t.Fatalf("native owner did not issue its source challenge: %v", lines.Err())
	}
	var challenge authorityv1.IdentitySourceChallenge
	if err := connectorruntime.ReadJSON(bytes.NewReader(lines.Bytes()), &challenge); err != nil {
		t.Fatal(err)
	}
	validateFixtureChallenge(t, challenge, start, "visitor_prepare")
	if err := json.NewEncoder(input).Encode(authorityv1.IdentitySourceReply{Schema: 1, ChallengeId: challenge.Id, Assertion: assertion}); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	if !lines.Scan() {
		t.Fatalf("native owner did not become ready: %v", lines.Err())
	}
	if err := connectorruntime.ReadJSON(bytes.NewReader(lines.Bytes()), &state); err != nil || state.Environment == nil || state.Environment.Environment != start.Selection.Environment || state.PID != command.Process.Pid {
		t.Fatal("native owner readiness changed the selected environment or process", err)
	}
	return state, challenge.NativePublicKey, stopOwner
}

func fixtureEnvironmentIPC(t *testing.T, path, operation, service string, reply *authorityv1.IdentitySourceReply, result any) {
	t.Helper()
	handle, err := connectorruntime.ReadHandle(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Service: service, IdentityReply: reply})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, handle.URL+"/v1/connections/"+operation, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+handle.Key)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("canonical native IPC %s status=%d", operation, response.StatusCode)
	}
	if err := connectorruntime.ReadJSON(response.Body, result); err != nil {
		t.Fatal(err)
	}
}

func prepareFixtureEnvironment(t *testing.T, owner connectorruntime.Status, service string, reply *authorityv1.IdentitySourceReply, nativeCall bool) connectorruntime.Prepared {
	t.Helper()
	var prepared connectorruntime.Prepared
	if nativeCall {
		handle, err := connectorruntime.ReadHandle(owner.ConnectionHandle)
		if err != nil {
			t.Fatal(err)
		}
		if err := connectorruntime.Call(t.Context(), owner.ConnectionHandle, "prepare", connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Service: service, IdentityReply: reply}, &prepared); err != nil {
			t.Fatal(err)
		}
	} else {
		fixtureEnvironmentIPC(t, owner.ConnectionHandle, "prepare", service, reply, &prepared)
	}
	if !reflect.DeepEqual(prepared.Environment, owner.Environment) {
		t.Fatal("native preparation replaced the owner's saved environment binding")
	}
	return prepared
}

// the native owner must supply its qualified exact operation trace before this
// fixture can pin the replacement for the retired twelve-call flow. absence is
// a blocking assertion, not a skipped check or permission to guess a bound.
var canonicalFixtureColdBudget map[string]int

func assertFixtureColdBudget(t *testing.T, calls map[string]int) {
	t.Helper()
	if len(canonicalFixtureColdBudget) == 0 {
		t.Fatalf("canonical cold RPC budget awaits the native owner's qualified operation trace; observed=%v", calls)
	}
	if !maps.Equal(calls, canonicalFixtureColdBudget) {
		t.Fatalf("canonical cold RPC budget differs: got=%v want=%v", calls, canonicalFixtureColdBudget)
	}
}
