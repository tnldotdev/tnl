package config

import (
	"strings"
	"testing"

	"github.com/0xcadams/tnl/internal/credentials"
)

func TestParseTNLD(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "/from-env")

	config, err := ParseTNLD(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.StateDir != "/from-env" {
		t.Fatalf("StateDir = %q, want /from-env", config.StateDir)
	}
	if config.Mode != TNLDModeStandalone {
		t.Fatalf("Mode = %q, want %q", config.Mode, TNLDModeStandalone)
	}
	if config.MetricsListen != "127.0.0.1:9090" {
		t.Fatalf("MetricsListen = %q, want 127.0.0.1:9090", config.MetricsListen)
	}
	if config.MaxActiveHostnameClaims != 128 {
		t.Fatalf("MaxActiveHostnameClaims = %d, want 128", config.MaxActiveHostnameClaims)
	}
	if config.MaxHostnameClaimRequests != 1024 {
		t.Fatalf("MaxHostnameClaimRequests = %d, want 1024", config.MaxHostnameClaimRequests)
	}

	config, err = ParseTNLD([]string{
		"--mode", "edge",
		"--state-dir", "/from-flag",
		"--metrics-listen", "[::1]:9091",
		"--max-active-hostname-claims", "16",
		"--max-hostname-claim-requests", "32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.StateDir != "/from-flag" {
		t.Fatalf("StateDir = %q, want /from-flag", config.StateDir)
	}
	if config.Mode != TNLDModeEdge {
		t.Fatalf("Mode = %q, want %q", config.Mode, TNLDModeEdge)
	}
	if config.MetricsListen != "[::1]:9091" {
		t.Fatalf("MetricsListen = %q, want [::1]:9091", config.MetricsListen)
	}
	if config.MaxActiveHostnameClaims != 16 || config.MaxHostnameClaimRequests != 32 {
		t.Fatalf("hostname claim quotas = %d, %d, want 16, 32",
			config.MaxActiveHostnameClaims, config.MaxHostnameClaimRequests)
	}
}

func TestParseTNLDHostnameClaimQuotaEnvironment(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "/state")
	t.Setenv("TNLD_MAX_ACTIVE_HOSTNAME_CLAIMS", "24")
	t.Setenv("TNLD_MAX_HOSTNAME_CLAIM_REQUESTS", "48")

	config, err := ParseTNLD(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxActiveHostnameClaims != 24 || config.MaxHostnameClaimRequests != 48 {
		t.Fatalf("hostname claim quotas = %d, %d, want 24, 48",
			config.MaxActiveHostnameClaims, config.MaxHostnameClaimRequests)
	}
}

func TestParseTNLDWorkerDoesNotRequireState(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "")
	t.Setenv("TNLD_METRICS_LISTEN", "")
	workerToken, _, err := credentials.NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}

	config, err := ParseTNLD([]string{
		"--mode", "worker",
		"--worker-url", "wss://edge.example/internal/v1/worker",
		"--worker-token", workerToken.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != TNLDModeWorker {
		t.Fatalf("Mode = %q, want %q", config.Mode, TNLDModeWorker)
	}
	if config.StateDir != "" {
		t.Fatalf("StateDir = %q, want empty", config.StateDir)
	}
	if config.MetricsListen != "" {
		t.Fatalf("MetricsListen = %q, want empty", config.MetricsListen)
	}
}

func TestParseTNLDRejectsInvalidInput(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "")

	for name, args := range map[string][]string{
		"missing state directory":  nil,
		"empty state directory":    {"--state-dir", "   "},
		"unknown flag":             {"--state-dir", "/state", "--unknown"},
		"unknown mode":             {"--state-dir", "/state", "--mode", "router"},
		"missing metrics port":     {"--state-dir", "/state", "--metrics-listen", "127.0.0.1"},
		"invalid metrics port":     {"--state-dir", "/state", "--metrics-listen", "127.0.0.1:nope"},
		"metrics whitespace":       {"--state-dir", "/state", "--metrics-listen", " 127.0.0.1:9090"},
		"zero active claims":       {"--state-dir", "/state", "--max-active-hostname-claims", "0"},
		"negative claim requests":  {"--state-dir", "/state", "--max-hostname-claim-requests", "-1"},
		"requests below active":    {"--state-dir", "/state", "--max-active-hostname-claims", "10", "--max-hostname-claim-requests", "9"},
		"active claims too large":  {"--state-dir", "/state", "--max-active-hostname-claims", "100001", "--max-hostname-claim-requests", "100001"},
		"claim requests too large": {"--state-dir", "/state", "--max-hostname-claim-requests", "100001"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTNLD(args); err == nil {
				t.Fatal("ParseTNLD succeeded")
			}
		})
	}
}

func TestTNLDValidateExternalAuthentication(t *testing.T) {
	workloadToken, _, err := credentials.NewWorkloadToken()
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseTNLD([]string{"--state-dir", "/state"})
	if err != nil {
		t.Fatal(err)
	}
	config.ExternalAuthIssuer = "https://account.example"
	config.ExternalAuthDeviceURL = "https://account.example/api/auth/device/code"
	config.ExternalAuthTokenURL = "https://account.example/api/auth/device/token"
	config.ExternalAuthClientID = "tnl-cli"
	config.ExternalAuthScope = "tnl:core"
	config.ExternalAuthIntrospectURL = "https://account.example/v1/auth/introspect"
	config.ExternalAuthToken = workloadToken.String()
	if err := config.Validate(); err != nil {
		t.Fatalf("valid external authentication: %v", err)
	}

	foreignEndpoint := config
	foreignEndpoint.ExternalAuthIntrospectURL = "https://attacker.example/introspect"
	if err := foreignEndpoint.Validate(); err == nil {
		t.Fatal("foreign introspection origin accepted")
	}
	multipleScopes := config
	multipleScopes.ExternalAuthScope = "openid tnl:core"
	if err := multipleScopes.Validate(); err == nil {
		t.Fatal("multiple external scopes accepted as one required scope")
	}
}

func TestTNLDValidateACME(t *testing.T) {
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	valid := TNLD{
		Mode: TNLDModeStandalone, StateDir: "/state", ControlHostname: "control.example.com", RouteSuffix: "example.com",
		PublicListen: "127.0.0.1:443", ControlCertFile: "/control.crt", ControlKeyFile: "/control.key",
		BootstrapToken: bootstrap.String(), RelayMapFile: "/relay.json", RelayProfile: "default",
		WorkerCapacity: 1, WorkerStreamLimit: 1, PublicConnLimit: 1, RouteConnLimit: 1, DrainTimeout: 30,
		MaxActiveHostnameClaims: 128, MaxHostnameClaimRequests: 1024,
		ACMEDirectoryURL: "https://acme.example/directory", ACMEEmail: "operator@example.com", ACMEProfile: "tlsserver",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid ACME config: %v", err)
	}
	automaticControl := valid
	automaticControl.ControlCertFile = ""
	automaticControl.ControlKeyFile = ""
	if err := automaticControl.Validate(); err != nil {
		t.Fatalf("automatic control config: %v", err)
	}
	missingControlTLS := automaticControl
	missingControlTLS.ACMEDirectoryURL = ""
	missingControlTLS.ACMEEmail = ""
	if err := missingControlTLS.Validate(); err == nil {
		t.Fatal("control config without ACME or a manual keypair succeeded")
	}
	for name, mutate := range map[string]func(*TNLD){
		"non-HTTPS directory":  func(config *TNLD) { config.ACMEDirectoryURL = "http://acme.example/directory" },
		"invalid email":        func(config *TNLD) { config.ACMEEmail = "Operator <operator@example.com>" },
		"missing ingress":      func(config *TNLD) { config.PublicListen = "" },
		"invalid control host": func(config *TNLD) { config.ControlHostname = "Control.example.com" },
		"long route suffix":    func(config *TNLD) { config.RouteSuffix = strings.Repeat("a.", 95) + "a" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
		})
	}
}
