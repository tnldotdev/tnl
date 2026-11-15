package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationRuntimeProvisionsPrimaryIngressPool(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, role := range []daemonconfig.Role{daemonconfig.RoleControl, daemonconfig.RoleStandalone} {
		for _, test := range []struct {
			name, ipv4, ipv6 string
		}{
			{name: "ipv4", ipv4: "192.0.2.10"},
			{name: "ipv6", ipv6: "2001:db8::10"},
			{name: "dual-stack", ipv4: "192.0.2.10", ipv6: "2001:db8::10"},
			{name: "unconfigured"},
		} {
			t.Run(string(role)+"/"+test.name, func(t *testing.T) {
				databaseURL, inspect := standaloneTestDatabase(t)
				owner := newRuntimeTopology(t)
				acme := standaloneTestACMEServer(t, owner)
				listener, packet := serviceRuntimeListener(t, owner), integrationPacketListener(t, owner)
				cfg, listeners := standalonePublishConfig(t, databaseURL, listener, packet, acme.URL+"/directory", owner)
				cfg.Role = role
				cfg.IngressIPv4Addresses, cfg.IngressIPv6Addresses = nil, nil
				if test.ipv4 != "" {
					cfg.IngressIPv4Addresses = []string{test.ipv4}
				}
				if test.ipv6 != "" {
					cfg.IngressIPv6Addresses = []string{test.ipv6}
				}
				cfg.Route53ServerZoneID = ""
				if test.ipv4 == "" && test.ipv6 == "" {
					cfg.Route53ManagedZoneID = ""
				}
				ca := newIntegrationTestCA(t)
				controlCertificate := ca.issueServer(t, cfg.ServerHostname(), owner)
				cfg.ControlTLSCertificateFile, cfg.ControlTLSPrivateKeyFile = controlCertificate.certificateFile, controlCertificate.privateKeyFile
				if role == daemonconfig.RoleControl {
					cfg.ClusterSecret = testClusterSecret
					listeners.privateControl = serviceRuntimeListener(t, owner)
					cfg.PrivateControlListen = listeners.privateControl.Addr().String()
				} else {
					certificate := ca.issueServer(t, cfg.StandaloneRelayHostname(), owner)
					cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile = certificate.certificateFile, certificate.privateKeyFile
				}
				if err := cfg.Validate(); err != nil {
					t.Fatal(err)
				}
				assertPool := func(state, ipv4, ipv6 string) {
					t.Helper()
					var actualState, actualIPv4, actualIPv6 string
					if err := inspect.QueryRowContext(integrationOperationContext(t), `SELECT state,
						coalesce(host(ipv4_address),''),coalesce(host(ipv6_address),'')
						FROM control.ingress_pools WHERE id=$1`, controlstate.PrimaryIngressPoolID).Scan(&actualState, &actualIPv4, &actualIPv6); err != nil {
						t.Fatal(err)
					}
					if actualState != state || actualIPv4 != ipv4 || actualIPv6 != ipv6 {
						t.Fatalf("primary ingress pool = %s/%s/%s, want %s/%s/%s", actualState, actualIPv4, actualIPv6, state, ipv4, ipv6)
					}
				}
				readPorts := func() string {
					t.Helper()
					var ports string
					if err := inspect.QueryRowContext(integrationOperationContext(t), `SELECT coalesce(
						string_agg(first_port::text||'-'||last_port::text,',' ORDER BY first_port),'')
						FROM control.ingress_service_port_ranges WHERE ingress_pool_id=$1`, controlstate.PrimaryIngressPoolID).Scan(&ports); err != nil {
						t.Fatal(err)
					}
					return ports
				}
				assertPool("disabled", "", "")
				options := integrationProcessOptions{owner: owner, acmeHTTPClient: acme.Client(), dns: newPrivateFixtureDNS(t, owner), listeners: listeners}
				process := startIntegrationProcessWithOptions(t, cfg, options)
				waitForProcessReady(t, process)
				state := "enabled"
				if test.ipv4 == "" && test.ipv6 == "" {
					state = "disabled"
				}
				assertPool(state, test.ipv4, test.ipv6)
				inventory, err := cfg.ServicePortInventory()
				if err != nil {
					t.Fatal(err)
				}
				var ranges []string
				for _, portRange := range inventory.Ranges() {
					ranges = append(ranges, fmt.Sprintf("%d-%d", portRange.First, portRange.Last))
				}
				wantPorts := strings.Join(ranges, ",")
				if actual := readPorts(); actual != wantPorts {
					t.Fatalf("startup service port inventory = %s, want %s", actual, wantPorts)
				}
				if test.name == "dual-stack" {
					assertRejected := func(rejected daemonconfig.Config, want string) {
						t.Helper()
						// a rejected pool must stop startup before listeners or port
						// inventory change, even when the proposed inventory differs.
						rejected.ServicePortRanges = nil
						ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
						defer cancel()
						err := serveRuntime(ctx, rejected, runtimeOptions{acmeHTTPClient: acme.Client(), serviceHTTPClient: &http.Client{Timeout: time.Second}})
						if err == nil || !strings.Contains(err.Error(), "provision primary ingress pool") || !strings.Contains(err.Error(), want) {
							t.Fatalf("pool rejection did not fail startup: %v", err)
						}
						if actual := readPorts(); actual != wantPorts {
							t.Fatalf("rejected startup replaced service ports: %s, want %s", actual, wantPorts)
						}
					}
					changed := cfg
					changed.IngressIPv4Addresses = []string{"192.0.2.20"}
					assertRejected(changed, "address differs")
					assertPool("enabled", test.ipv4, test.ipv6)
					ambiguous := cfg
					ambiguous.IngressIPv4Addresses = []string{test.ipv4, "192.0.2.20"}
					assertRejected(ambiguous, "at most one")
					assertPool("enabled", test.ipv4, test.ipv6)
					if _, err := inspect.ExecContext(integrationOperationContext(t), `UPDATE control.ingress_pools SET state='draining' WHERE id=$1`, controlstate.PrimaryIngressPoolID); err != nil {
						t.Fatal(err)
					}
					assertRejected(cfg, "address differs")
					assertPool("draining", test.ipv4, test.ipv6)
				}
				stopIntegrationProcess(t, process)
			})
		}
	}
}

// only explicit, non-secret response fields are logged. preserve the response
// bytes and closer for the real client; never log headers or challenge material.
func traceRuntimeCertificateHTTP(t *testing.T, client *http.Client, start time.Time) {
	base := client.Transport
	var observations atomic.Int64
	client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
		at := time.Now()
		response, err := base.RoundTrip(request)
		path := request.URL.Path
		if !strings.Contains(path, "/certificate-issuances") && !strings.HasSuffix(path, "/certificate-installed") &&
			!(strings.Contains(path, "/publish-runs/") && strings.HasSuffix(path, "/ready")) {
			return response, err
		}
		if observations.Add(1) > 4096 {
			return response, err
		}
		if err != nil {
			t.Logf("provision_http elapsed=%s path=%s failed=true", time.Since(start), path)
			return response, err
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body = struct {
			io.Reader
			io.Closer
		}{bytes.NewReader(body), response.Body}
		var value struct {
			ID             string     `json:"id"`
			State          string     `json:"state"`
			RetryAt        *time.Time `json:"retry_at"`
			CertificatePEM *string    `json:"certificate_pem"`
		}
		_ = json.Unmarshal(body, &value)
		t.Logf("provision_http elapsed=%s duration=%s path=%s status=%d issuance=%s state=%s retry_at=%v material=%t read_error=%v",
			time.Since(start), time.Since(at), path, response.StatusCode, value.ID, value.State, value.RetryAt, value.CertificatePEM != nil, readErr)
		return response, err
	})
}

// sample at 250ms while activating, logging only state transitions. this is a
// test-only observer on the inspection connection, not a worker or metrics hook.
// attempts/epochs retain evidence of short claims between samples. the timestamps
// are database transition times; elapsed is the observation time.
func traceRuntimeCertificateState(t *testing.T, database *sql.DB, start time.Time) func() {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		previous := make(map[string]string)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			sampleCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			rows, err := database.QueryContext(sampleCtx, `SELECT o.id, jsonb_build_object(
				'hostname', s.certificate_hostname, 'state', o.state, 'created_at', o.created_at,
				'updated_at', o.updated_at, 'available_at', o.available_at, 'attempts', o.attempts,
				'claimed', o.work_owner IS NOT NULL, 'epoch', o.work_epoch,
				'installed_at', o.installed_at, 'certificate_expires_at', s.certificate_expires_at, 'session_state', s.state,
				'authorizations', (SELECT jsonb_agg(jsonb_build_object('state', a.state,
					'updated_at', a.updated_at, 'presented_at', a.presented_at) ORDER BY a.id)
					FROM control.acme_authorizations a WHERE a.order_id = o.id)
			)::text, clock.current_revision,
			coalesce((SELECT min(i.routing_table_revision) FROM control.ingress_leases i
				WHERE NOT i.draining AND i.lease_expires_at > now()), -1)
			FROM control.acme_orders o JOIN control.service_runs s ON s.id = o.service_run_id
			CROSS JOIN control.ingress_routing_table_clock clock ORDER BY o.id`)
			if err == nil {
				for rows.Next() {
					var id, state string
					var head, applied int64
					if err = rows.Scan(&id, &state, &head, &applied); err != nil {
						break
					}
					if previous[id] != state {
						t.Logf("provision_state elapsed=%s issuance=%s head=%d applied=%d state=%s", time.Since(start), id, head, applied, state)
						previous[id] = state
					}
				}
				if err == nil {
					err = rows.Err()
				}
				_ = rows.Close()
			}
			stop()
			if err != nil && ctx.Err() == nil {
				t.Errorf("provisioning timeline: %v", err)
				return
			}
		}
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(stop)
	return stop
}
