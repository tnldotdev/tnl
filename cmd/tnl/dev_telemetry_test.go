package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDevLateFrameworkIsIncludedInReadyTelemetry(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithCancel(devBootstrapTestContext(t))
	defer cancel()
	readyRequested, allowReady := make(chan struct{}), make(chan struct{})
	var requested sync.Once
	fixture := testutil.NewPublishingFixture(t, testutil.PublishingHooks{
		Ready: func(ctx context.Context, _ controlv1.PublishRunSetup) error {
			requested.Do(func() { close(readyRequested) })
			select {
			case <-allowReady:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	// a forced port can already be listening before framework configuration
	// registers. keep a real child alive while the test acts as its integration.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer origin.Close()
	root, stateRoot := t.TempDir(), filepath.Join(t.TempDir(), "state")
	flags := devCommand{
		remoteFlags: remoteFlags{ServerURL: fixture.URL, StateDir: stateRoot, AccessToken: fixture.AccessToken},
		tunnelFlags: tunnelFlags{PublicURL: "https://late." + fixture.Namespace, AllowAllIPs: true},
		Command:     []string{"sh", "-c", "sleep 30"}, Port: origin.Listener.Addr().(*net.TCPAddr).Port,
		StartupTimeout: 3 * time.Second, projectRoot: root, commandDir: root,
	}
	var diagnostics devTelemetryBuffer
	events := make(chan telemetryPayload, 4)
	done := make(chan error, 1)
	go func() {
		done <- runDev(ctx, flags, nil, io.Discard, &diagnostics, telemetryReporterFunc(func(event telemetryPayload) { events <- event }))
	}()
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Error("runDev did not stop during cleanup")
			}
		}
	})
	select {
	case <-readyRequested:
	case err := <-done:
		joined = true
		t.Fatalf("publisher exited before readiness: %v\n%s", err, diagnostics.String())
	case <-ctx.Done():
		t.Fatal("publisher did not request readiness")
	}
	directory, err := devRuntimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := &devBootstrap{socket: filepath.Join(directory, "dev-"+devSocketDigest(root, "")+".sock")}
	configured := postDevRequest(bootstrap, "/v1/configure", devConfigurationRequest{Protocol: 1, Framework: "next"})
	if configured.err != nil || configured.status != http.StatusOK {
		t.Fatalf("late configure: %+v", configured)
	}
	targeted := postDevRequest(bootstrap, "/v1/target", devTargetRequest{Protocol: 1, Framework: "next", Target: origin.URL})
	if targeted.err != nil || targeted.status != http.StatusNoContent {
		t.Fatalf("late target: %+v", targeted)
	}
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	for {
		snapshot, err := state.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Tunnels) == 1 && snapshot.Tunnels[0].Framework == "next" {
			break
		}
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			t.Fatal("late framework was not saved")
		}
	}
	// SetDevTarget runs just before the framework result is delivered to
	// runDev's event loop. allow the loop to consume it before releasing ready;
	// the displayed framework below independently checks that ordering.
	time.Sleep(50 * time.Millisecond)
	close(allowReady)
	var event telemetryPayload
	select {
	case event = <-events:
	case <-ctx.Done():
		t.Fatal("ready telemetry was not emitted")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("runDev: %v", err)
	}
	joined = true
	if !strings.Contains(diagnostics.String(), "next") {
		t.Fatalf("fixture did not incorporate framework before readiness:\n%s", diagnostics.String())
	}
	if event.Event != "publish_run_started" || event.Command != "dev" || event.Framework != "next" {
		t.Errorf("ready telemetry = %+v; want framework next already present in ready output", event)
	}
	if len(events) != 0 {
		t.Error("ready telemetry was emitted more than once")
	}
}

// child stderr and publisher lifecycle output can write concurrently.
type devTelemetryBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *devTelemetryBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *devTelemetryBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
