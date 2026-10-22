package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestRunVersion(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), []string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != buildinfo.Line("tnld")+"\n" {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestWriteTerminalErrorRendersJoinedErrorsOnOneSafeLine(t *testing.T) {
	var output bytes.Buffer
	writeTerminalError(&output, errors.Join(errors.New("first"), errors.New("second\x1b")))
	if got := output.String(); !strings.HasPrefix(got, "tnld: run tnld: the operation failed unexpectedly;") ||
		strings.Contains(got, "first") || strings.Contains(got, "second") || strings.ContainsRune(got, '\x1b') ||
		strings.Count(got, "\n") != 1 {
		t.Fatalf("terminal error = %q", got)
	}
}

func TestWriteTerminalErrorUsesTypedOperatorCopy(t *testing.T) {
	var output bytes.Buffer
	writeTerminalError(&output, failure.WrapSetting("validate storage key", failure.ServerStorageKeyInvalid, failure.SettingStorageKey,
		errors.New("storagekey: key=secret-do-not-print")))
	want := "tnld: validate storage key TNLD_STORAGE_KEY: storage key is missing or invalid; " +
		"set an unpadded base64url 32-byte key for control, then retry\n"
	if output.String() != want {
		t.Fatalf("terminal error = %q, want %q", output.String(), want)
	}
}

func TestRunMigrateRequiresDirectURL(t *testing.T) {
	t.Setenv("TNLD_DATABASE_DIRECT_URL", "")
	err := run(t.Context(), []string{"migrate"}, new(bytes.Buffer))
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.DirectDatabaseURLMissing {
		t.Fatalf("migrate error = %v", err)
	}
}

func TestLoginTokenCommandIsRetired(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), []string{"login-token"}, &output); err == nil {
		t.Fatal("retired login token command accepted")
	}
}

func TestRunConfigCheckIsSilentAndDoesNotStartServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.yml")
	contents := `version: 1
tnld:
  role: relay
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
	contents := `{"version":1,"tnld":{"role":"relay","metrics_listen":"file:1","relay_stream_capacity":12}}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNLD_METRICS_LISTEN", "env:2")
	base := tnldconfig.Config{
		Role: tnldconfig.RoleRelay, MetricsListen: "env:2", RelayStreamCapacity: 99, PublicURLCertificateWorkers: 4,
		ControlHostname: "control.example.com", ClusterSecret: "0123456789abcdef0123456789abcdef",
		RelayServiceID: "relay-test", RelayID: "relay-test", RelayAddress: "relay.example.com:443",
		InternalRelayAddress: "relay.internal:9443", RelayTCPListen: ":443", RelayUDPListen: ":443",
		VisitorConnectionLimit: 1, PublisherConnectionLimit: 1, QUICMaxIncomingStreams: 1,
		ClientHelloConnectionLimit:       1024,
		StandaloneControlConnectionLimit: 1024, StandaloneRelayConnectionLimit: 4096,
		QUICIdleTimeout: time.Second, IngressLeaseDuration: 3 * time.Second,
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
	for _, flag := range []string{
		"--state-dir", "--backup-url", "--relay-map-file", "--edge-url", "--worker-token",
		"--reserved-route-name", "--tunnel-fallback-delay",
	} {
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
	parsed, err := parser.Parse([]string{"serve", "--role", "relay", "--control-hostname", "control.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "serve" || flags.Serve.Values.Role != tnldconfig.RoleRelay || flags.Serve.Values.ControlHostname != "control.example.com" {
		t.Fatalf("serve values = %#v", flags.Serve.Values)
	}
}

func TestOIDCAdmissionFileRelativeToConfigAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tnl.yml")
	contents := `version: 1
tnld:
  role: control
  database_url: postgres://tnl:secret@database.example/tnl
  server_domain: tnl.example.com
  managed_domain: tunnels.example.com
  cluster_secret: 0123456789abcdef0123456789abcdef
  storage_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  acme_email: operator@example.com
  acme_accept_terms: true
  oidc_issuer: https://identity.example.test
  oidc_client_id: server
  oidc_admission_file: admissions.json
  private_control_tls_certificate_file: control.pem
  private_control_tls_private_key_file: control.key
`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	t.Run("config_check_requires_internal_tls", func(t *testing.T) {
		missing := strings.ReplaceAll(contents, "  private_control_tls_certificate_file: control.pem\n", "")
		missing = strings.ReplaceAll(missing, "  private_control_tls_private_key_file: control.key\n", "")
		file := filepath.Join(dir, "missing-tls.yml")
		if err := os.WriteFile(file, []byte(missing), 0600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err := run(t.Context(), []string{"config", "check", "--config", file}, &output)
		typed, ok := failure.Of(err)
		if !ok || typed.Reason() != failure.ServerConfigInvalid || typed.Setting() != failure.SettingPrivateControlCert || output.Len() != 0 {
			t.Fatalf("missing private control TLS: err=%v stdout=%q", err, output.String())
		}
	})
	for _, precedence := range []string{"file", "env", "flag"} {
		t.Run(precedence, func(t *testing.T) {
			base, err := parseDefaultsAndEnvironment()
			if err != nil {
				t.Fatal(err)
			}
			flags := map[string]bool{}
			want := filepath.Join(dir, "admissions.json")
			if precedence != "file" {
				want, base.OIDCAdmissionFile = "override.json", "override.json"
				if precedence == "env" {
					t.Setenv("TNLD_OIDC_ADMISSION_FILE", "override.json")
				} else {
					flags["oidc_admission_file"] = true
				}
			}
			cfg, err := resolveConfigFile(path, base, flags)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OIDCAdmissionFile != want {
				t.Fatalf("admission path = %q, want %q", cfg.OIDCAdmissionFile, want)
			}
		})
	}
}
