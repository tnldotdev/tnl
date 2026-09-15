package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestRunVersion(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), []string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "tnld ") {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestRunMigrateRequiresDirectURL(t *testing.T) {
	t.Setenv("TNLD_DATABASE_DIRECT_URL", "")
	err := run(t.Context(), []string{"migrate"}, new(bytes.Buffer))
	if err == nil || err.Error() != "TNLD_DATABASE_DIRECT_URL is required" {
		t.Fatalf("migrate error = %v", err)
	}
}

func TestRunLoginToken(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), []string{"login-token"}, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.ParseLoginToken(credentials.LoginToken(strings.TrimSpace(output.String()))); err != nil {
		t.Fatalf("generated login token: %v", err)
	}
}

func TestRunConfigCheckIsSilentAndDoesNotStartServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.yml")
	contents := `version: 1
tnld:
  mode: relay
  control_hostname: control.example.com
  cluster_secret: 0123456789abcdef0123456789abcdef
  relay_service_id: relay-test
  relay_id: relay-test
  relay_address: relay.example.com:443
  internal_relay_address: relay.internal:9443
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(t.Context(), []string{"config", "check", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q", output.String())
	}
}

func TestResolveConfigFileRespectsEnvironmentAndFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.json")
	contents := `{"version":1,"tnld":{"mode":"relay","metrics_listen":"file:1","relay_stream_capacity":12}}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNLD_METRICS_LISTEN", "env:2")
	base := tnldconfig.Config{
		Mode: tnldconfig.RoleRelay, MetricsListen: "env:2", RelayStreamCapacity: 99,
		ControlHostname: "control.example.com", ClusterSecret: "0123456789abcdef0123456789abcdef",
		RelayServiceID: "relay-test", RelayID: "relay-test", RelayAddress: "relay.example.com:443",
		InternalRelayAddress: "relay.internal:9443", RelayTCPListen: ":443", RelayUDPListen: ":443",
		PublicConnectionLimit: 1, RouteConnectionLimit: 1, PublisherConnectionLimit: 1, QUICMaxIncomingStreams: 1,
		QUICIdleTimeout: time.Second, TunnelFallbackDelay: time.Second, IngressLeaseDuration: 3 * time.Second,
		RelayLeaseDuration: 3 * time.Second, LeaseRenewalInterval: time.Second, ControlRetryInterval: time.Second,
		RoutingTableWait: time.Second, DrainTimeout: time.Second,
	}
	resolved, err := resolveConfigFile(path, base, map[string]bool{"relay_stream_capacity": true})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.MetricsListen != "env:2" || resolved.RelayStreamCapacity != 99 {
		t.Fatalf("resolved config = %#v", resolved)
	}
}

func TestParserRejectsRemovedServeFlags(t *testing.T) {
	for _, flag := range []string{"--state-dir", "--backup-url", "--relay-map-file", "--edge-url", "--worker-token"} {
		var flags tnldCLI
		parser, err := newTNLDParser(&flags, new(bytes.Buffer))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse([]string{"serve", flag, "value"}); err == nil {
			t.Fatalf("removed flag %q was accepted", flag)
		}
	}
}

func TestParserAcceptsServeValuesBeforeFileResolution(t *testing.T) {
	var flags tnldCLI
	parser, err := newTNLDParser(&flags, new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"serve", "--mode", "relay", "--control-hostname", "control.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "serve" || flags.Serve.Values.Mode != tnldconfig.RoleRelay || flags.Serve.Values.ControlHostname != "control.example.com" {
		t.Fatalf("serve values = %#v", flags.Serve.Values)
	}
}
