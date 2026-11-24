package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func TestControlOutageToleranceConfigResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.yml")
	document := `version: 1
tnld:
  role: standalone
  database_url: postgres://tnl:secret@database.example/tnl
  server_domain: tnl.example.com
  control_proxy_provider: single-xff
  managed_domain: tunnels.example.com
  route53_server_zone_id: ZSERVER
  acme_email: operator@example.com
  acme_accept_terms: true
  oidc_issuer: https://identity.example.test
  oidc_client_id: server
  storage_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  control_outage_tolerance: 90s
`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, environment string
		flags             []string
		want              time.Duration
	}{
		{"file", "", nil, 90 * time.Second},
		{"environment", "2m", nil, 2 * time.Minute},
		{"flag", "2m", []string{"--control-outage-tolerance", "3m"}, 3 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.environment != "" {
				t.Setenv("TNLD_CONTROL_OUTAGE_TOLERANCE", test.environment)
			}
			var flags tnldCLI
			parser := parseServerForTest(&flags, new(bytes.Buffer))
			parsed, err := parser(append([]string{"serve", "--config", path}, test.flags...))
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := resolveServeCommand(flags.Serve.ConfigPath, daemonconfig.Config(flags.Serve.Values), parsed)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.ControlOutageTolerance != test.want {
				t.Fatalf("tolerance = %v, want %v", resolved.ControlOutageTolerance, test.want)
			}
		})
	}
	var output bytes.Buffer
	if err := run(t.Context(), []string{"config", "check", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("config check emitted output: %q", output.String())
	}
}
