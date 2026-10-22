package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

// an ordinary app keeps its own listener. the local tnl runtime publishes it
// after confirming the current registration and stops publishing when it ends.
func TestBinaryIntegrationAppLedPublisher(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t, "simple")
	t.Cleanup(func() {
		if t.Failed() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			inspect := inspectStandaloneTestDatabase(t, fixture.databaseURL)
			rows, err := inspect.QueryContext(ctx, `
				SELECT run.state, run.certificate_installed_at IS NOT NULL, slot.connection_slot, slot.state
				FROM control.publish_runs AS run
				JOIN control.public_urls AS public_url ON public_url.id = run.public_url_id
				LEFT JOIN control.publish_run_connection_slots AS slot ON slot.publish_run_id = run.id
				WHERE public_url.canonical_hostname = $1 ORDER BY run.publish_run_number, slot.connection_slot`,
				"app-led-binary.routes.127.0.0.1.nip.io")
			if err == nil {
				for rows.Next() {
					var runState string
					var certificateInstalled bool
					var slotNumber sql.NullInt64
					var slotState sql.NullString
					if err := rows.Scan(&runState, &certificateInstalled, &slotNumber, &slotState); err != nil {
						t.Logf("read publish run diagnostic: %v", err)
						break
					}
					t.Logf("publish run state=%s certificate_installed=%t slot=%d slot_state=%s", runState, certificateInstalled, slotNumber.Int64, slotState.String)
				}
				_ = rows.Close()
			} else {
				t.Logf("read publisher diagnostic: %v", err)
			}
			for _, table := range []string{"public_urls", "publisher_identities", "publisher_enrollments", "previews", "preview_public_urls"} {
				var count int
				if err := inspect.QueryRowContext(ctx, "SELECT count(*) FROM control."+table).Scan(&count); err == nil {
					t.Logf("app-led %s=%d", table, count)
				}
			}
			t.Logf("tnld output:\n%s", fixture.server.output.String())
		}
	})
	project := t.TempDir()
	initializeIntegrationBinaryProject(t, project, "app-led")
	configuration := []byte(`{"version":1,"tnl":{"server":"https://control.127.0.0.1.nip.io","services":{"api":{"name":"app-led-binary","target":{"type":"app"},"public_url":{"access":"anonymous"}}}}}`)
	if err := os.WriteFile(filepath.Join(project, "tnl.json"), configuration, 0600); err != nil {
		t.Fatal(err)
	}
	app := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Tnl-Fixture", "app-led")
		_, _ = io.WriteString(response, "app-led visitor")
	}))
	defer app.Close()
	runtimeProcess := startIntegrationBinaryProcess(t, project, fixture.environment, fixture.tnlPath, "runtime", "serve", "--directory", project)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("local publisher output:\n%s", runtimeProcess.output.String())
		}
	})
	started := startIntegrationBinaryProcess(t, project, fixture.environment, fixture.tnlPath, "runtime", "endpoint", "--directory", project, "--service", "api")
	if err := waitForDoneWithin(started.done, 30*time.Second); err != nil {
		t.Fatal("local publisher did not start")
	}
	assertIntegrationBinaryProcessResult(t, started)
	var endpoint publisherprotocol.Endpoint
	if err := json.Unmarshal([]byte(started.output.String()), &endpoint); err != nil || endpoint.Scope != "app" || endpoint.Service == nil || *endpoint.Service != "api" || endpoint.Capability == "" {
		t.Fatalf("runtime did not return the scoped api app endpoint: %v", err)
	}
	client := &http.Client{Timeout: 75 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	request := func(operation string, value any, target any) int {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		operationCtx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
		defer cancel()
		call, err := http.NewRequestWithContext(operationCtx, http.MethodPost, endpoint.Url+"/v1/"+operation, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("Authorization", "Bearer "+endpoint.Capability)
		response, err := client.Do(call)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if target != nil {
			if err := json.NewDecoder(response.Body).Decode(target); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode
	}
	state, err := clientstate.Open(integrationOperationContext(t), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	for index := 1; index <= 2; index++ {
		owner := fmt.Sprintf("%032x", index)
		var assigned publisherprotocol.Assignment
		if status := request("prepare", publisherprotocol.Prepare{Version: 1, Directory: project, Service: "api", Framework: "node", Owner: owner, PID: os.Getpid()}, &assigned); status != http.StatusOK {
			t.Fatalf("prepare status %d", status)
		}
		registration := publisherprotocol.Registration{Version: 1, RegistrationID: assigned.RegistrationID, Owner: owner, Target: app.URL}
		if status := request("register", registration, nil); status != http.StatusNoContent {
			t.Fatalf("register status %d", status)
		}
		// renewal belongs to the app. keep the fixture's registration current
		// while certificate issuance and public readiness finish.
		stopRenewal, renewalDone := make(chan struct{}), make(chan struct{})
		var renewalOnce sync.Once
		stop := func() {
			renewalOnce.Do(func() { close(stopRenewal) })
			<-renewalDone
		}
		t.Cleanup(stop)
		go func() {
			defer close(renewalDone)
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopRenewal:
					return
				case <-ticker.C:
					payload, _ := json.Marshal(publisherprotocol.Registration{Version: 1, RegistrationID: assigned.RegistrationID, Owner: owner})
					call, err := http.NewRequest(http.MethodPost, endpoint.Url+"/v1/renew", bytes.NewReader(payload))
					if err != nil {
						return
					}
					call.Header.Set("Content-Type", "application/json")
					call.Header.Set("Authorization", "Bearer "+endpoint.Capability)
					response, err := client.Do(call)
					if err != nil {
						return
					}
					_ = response.Body.Close()
				}
			}
		}()
		var tunnel clientstate.TunnelInfo
		waitForIntegrationCondition(t, 55*time.Second, func(ctx context.Context) (bool, error) {
			app, err := publisherapp.ReadSnapshot(project, fixture.stateDirectory)
			if err != nil {
				return false, err
			}
			if len(app.Services) != 1 || !app.Services[0].Routable {
				return false, fmt.Errorf("app publication is not routable: services=%+v", app.Services)
			}
			snapshot, err := state.SnapshotProject(ctx, project)
			if err != nil {
				return false, fmt.Errorf("read app tunnel after publication: %w; services=%+v", err, app.Services)
			}
			if len(snapshot.Tunnels) == 1 && snapshot.Tunnels[0].State == clientstate.TunnelStateReady {
				tunnel = snapshot.Tunnels[0]
				return true, nil
			}
			return false, fmt.Errorf("app publication is not ready: tunnels=%+v services=%+v", snapshot.Tunnels, app.Services)
		})
		if tunnel.PublicURL != assigned.PublicURL || tunnel.Target != app.URL || tunnel.PublishRunNumber != uint64(index) {
			t.Fatalf("app-led tunnel = %+v; assignment = %+v", tunnel, assigned)
		}
		waitForIntegrationCondition(t, 20*time.Second, func(ctx context.Context) (bool, error) {
			response, body, err := visitor.requestURLContext(ctx, http.MethodGet, assigned.PublicURL+"/", nil)
			return err == nil && response.StatusCode == http.StatusOK && response.Header.Get("X-Tnl-Fixture") == "app-led" && strings.Contains(string(body), "app-led visitor"), err
		})
		runIntegrationBinaryCommand(t, project, fixture.environment, fixture.tnlPath,
			"wait", "--service", "api", "--timeout", "30s", "--output=json")
		if status := request("unregister", registration, nil); status != http.StatusNoContent {
			t.Fatalf("unregister status %d", status)
		}
		stop()
		waitForIntegrationCondition(t, 15*time.Second, func(ctx context.Context) (bool, error) {
			snapshot, err := state.SnapshotProject(ctx, project)
			return err == nil && len(snapshot.Tunnels) == 0, err
		})
		if tunnel.PublicURLID == "" {
			t.Fatal("publication has no saved public URL")
		}
		if index == 1 {
			// a replaced app cannot reclaim its old registration.
			if status := request("register", registration, nil); status != http.StatusConflict {
				t.Fatalf("old registration accepted with status %d", status)
			}
		}
	}
}
