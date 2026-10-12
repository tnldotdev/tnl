package tnldruntime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

// an ordinary app keeps its own listener. the local tnl runtime publishes it
// after confirming the current registration and stops publishing when it ends.
func TestBinaryIntegrationAppLedPublisher(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	t.Cleanup(func() {
		if t.Failed() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			rows, err := inspectStandaloneTestDatabase(t, fixture.databaseURL).QueryContext(ctx, `
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
			t.Logf("tnld output:\n%s", fixture.server.output.String())
		}
	})
	project := t.TempDir()
	configuration := []byte(`{"version":1,"tnl":{"server":"https://control.127.0.0.1.nip.io","services":{"api":{"target":{"type":"app"},"tunnel":{"name":"app-led-binary","allow_all_ips":true}}}}}`)
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
	started := startIntegrationBinaryProcess(t, project, fixture.environment, fixture.tnlPath, "runtime", "endpoint", "--directory", project)
	if err := waitForDoneWithin(started.done, 30*time.Second); err != nil {
		t.Fatal("local publisher did not start")
	}
	assertIntegrationBinaryProcessResult(t, started)
	var location struct {
		Version int    `json:"version"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal([]byte(started.output.String()), &location); err != nil || location.Version != privateprotocol.Version || location.Path == "" {
		t.Fatalf("runtime endpoint response = %q, error %v", started.output.String(), err)
	}
	var endpoint struct {
		Version    int    `json:"version"`
		URL        string `json:"url"`
		Credential string `json:"credential"`
	}
	client := &http.Client{Timeout: 35 * time.Second, Transport: &http.Transport{Proxy: nil}}
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-runtimeProcess.done:
			t.Fatalf("local publisher exited before registration: %v\n%s", runtimeProcess.result(), runtimeProcess.output.String())
		default:
		}
		data, err := os.ReadFile(location.Path)
		if err != nil {
			return false, err
		}
		if err := json.Unmarshal(data, &endpoint); err != nil {
			return false, err
		}
		if endpoint.Version != privateprotocol.Version || endpoint.URL == "" || endpoint.Credential == "" {
			return false, errors.New("invalid local publisher endpoint descriptor")
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/v1/status", nil)
		if err != nil {
			return false, err
		}
		call.Header.Set("Authorization", "Bearer "+endpoint.Credential)
		response, err := client.Do(call)
		if err != nil {
			return false, err
		}
		response.Body.Close()
		return response.StatusCode == http.StatusOK, nil
	})
	request := func(operation string, value any, target any) int {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		operationCtx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
		defer cancel()
		call, err := http.NewRequestWithContext(operationCtx, http.MethodPost, endpoint.URL+"/v1/"+operation, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("Authorization", "Bearer "+endpoint.Credential)
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
		var assigned privateprotocol.Assignment
		if status := request("prepare", privateprotocol.Prepare{Version: 1, Directory: project, Service: "api", Framework: "node", Owner: owner, PID: os.Getpid()}, &assigned); status != http.StatusOK {
			t.Fatalf("prepare status %d", status)
		}
		registration := privateprotocol.Registration{Version: 1, RegistrationID: assigned.RegistrationID, Owner: owner, Target: app.URL}
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
					payload, _ := json.Marshal(privateprotocol.Registration{Version: 1, RegistrationID: assigned.RegistrationID, Owner: owner})
					call, err := http.NewRequest(http.MethodPost, endpoint.URL+"/v1/renew", bytes.NewReader(payload))
					if err != nil {
						return
					}
					call.Header.Set("Content-Type", "application/json")
					call.Header.Set("Authorization", "Bearer "+endpoint.Credential)
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
			app, err := clientruntime.ReadSnapshot(project, fixture.stateDirectory)
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

func TestBinaryIntegrationAppAndNamedServiceShareLocalPublisher(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	project := t.TempDir()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "one local service")
	}))
	defer app.Close()
	configuration := fmt.Sprintf(`{"version":1,"tnl":{"server":"https://control.127.0.0.1.nip.io","services":{"web":{"target":{"type":"app"},"tunnel":{"name":"shared-app-binary","allow_all_ips":true}},"orders":{"target":{"type":"address","address":%q},"tunnel":{"name":"shared-named-binary","allow_all_ips":true}}}}}`, app.URL)
	if err := os.WriteFile(filepath.Join(project, "tnl.json"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	runtimeProcess := startIntegrationBinaryProcess(t, project, fixture.environment, fixture.tnlPath, "runtime", "serve", "--directory", project)
	endpointCommand := startIntegrationBinaryProcess(t, project, fixture.environment, fixture.tnlPath, "runtime", "endpoint", "--directory", project)
	if err := waitForDoneWithin(endpointCommand.done, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	assertIntegrationBinaryProcessResult(t, endpointCommand)
	var location struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(endpointCommand.output.String()), &location); err != nil || location.Path == "" {
		t.Fatalf("runtime endpoint = %q, %v", endpointCommand.output.String(), err)
	}
	var endpoint struct {
		URL        string `json:"url"`
		Credential string `json:"credential"`
	}
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-runtimeProcess.done:
			return false, fmt.Errorf("local publisher exited: %v; %s", runtimeProcess.result(), runtimeProcess.output.String())
		default:
		}
		data, err := os.ReadFile(location.Path)
		if err != nil {
			return false, err
		}
		if err := json.Unmarshal(data, &endpoint); err != nil {
			return false, err
		}
		return endpoint.URL != "" && endpoint.Credential != "", nil
	})
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	call := func(operation string, payload any, target any) int {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint.URL+"/v1/"+operation, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
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
	owner := "0123456789abcdef0123456789abcdef"
	var assigned privateprotocol.Assignment
	if status := call("prepare", privateprotocol.Prepare{Version: 1, Directory: project, Service: "web", Framework: "node", Owner: owner, PID: os.Getpid()}, &assigned); status != http.StatusOK {
		t.Fatalf("app preparation returned %d", status)
	}
	registration := privateprotocol.Registration{Version: 1, RegistrationID: assigned.RegistrationID, Owner: owner, Target: app.URL}
	if status := call("register", registration, nil); status != http.StatusNoContent {
		t.Fatalf("app registration returned %d", status)
	}
	stopRenewal := make(chan struct{})
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenewal:
				return
			case <-ticker.C:
				body, _ := json.Marshal(registration)
				request, err := http.NewRequest(http.MethodPost, endpoint.URL+"/v1/renew", bytes.NewReader(body))
				if err != nil {
					return
				}
				request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
				request.Header.Set("Content-Type", "application/json")
				response, err := client.Do(request)
				if err != nil {
					return
				}
				response.Body.Close()
			}
		}
	}()
	var stopRenewalOnce sync.Once
	stopAppRenewal := func() {
		stopRenewalOnce.Do(func() { close(stopRenewal) })
		<-renewed
	}
	t.Cleanup(stopAppRenewal)
	named := startIntegrationBinaryProcess(t, project, fixture.environment, fixture.tnlPath, "publish", "orders", "--output=ndjson")
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	waitForIntegrationCondition(t, 75*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-named.done:
			return false, fmt.Errorf("named publisher exited: %v; %s", named.result(), named.output.String())
		default:
		}
		snapshot, err := clientruntime.ReadSnapshot(project, fixture.stateDirectory)
		if err != nil {
			return false, err
		}
		if len(snapshot.Services) != 2 || !snapshot.Services[0].Routable || !snapshot.Services[1].Routable {
			return false, fmt.Errorf("shared publisher has not made both services routable: %+v", snapshot.Services)
		}
		return true, nil
	})
	for _, url := range []string{assigned.PublicURL, "https://shared-named-binary.routes.127.0.0.1.nip.io"} {
		waitForIntegrationCondition(t, 20*time.Second, func(ctx context.Context) (bool, error) {
			response, body, err := visitor.requestURLContext(ctx, http.MethodGet, url+"/", nil)
			return err == nil && response.StatusCode == http.StatusOK && string(body) == "one local service", err
		})
	}
	if err := named.shutdown(15*time.Second, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	assertIntegrationBinaryProcessResult(t, named)
	waitForIntegrationCondition(t, 15*time.Second, func(ctx context.Context) (bool, error) {
		snapshot, err := clientruntime.ReadSnapshot(project, fixture.stateDirectory)
		return err == nil && len(snapshot.Services) == 2 && snapshot.Services[0].Registered == false && snapshot.Services[1].Registered, err
	})
	stopAppRenewal()
	if status := call("unregister", registration, nil); status != http.StatusNoContent {
		t.Fatalf("app unregister returned %d", status)
	}
	waitForIntegrationCondition(t, 15*time.Second, func(ctx context.Context) (bool, error) {
		snapshot, err := clientruntime.ReadSnapshot(project, fixture.stateDirectory)
		return err == nil && len(snapshot.Services) == 2 && !snapshot.Services[0].Registered && !snapshot.Services[1].Registered, err
	})
}
