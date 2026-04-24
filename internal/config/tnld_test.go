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

func TestTNLDValidateOIDC(t *testing.T) {
	config, err := ParseTNLD([]string{"--state-dir", "/state"})
	if err != nil {
		t.Fatal(err)
	}
	config.OIDCIssuer = "https://account.example"
	config.OIDCClientID = "tnl-cli"
	if err := config.Validate(); err != nil {
		t.Fatalf("valid OIDC: %v", err)
	}

	incomplete := config
	incomplete.OIDCClientID = ""
	if err := incomplete.Validate(); err == nil {
		t.Fatal("incomplete OIDC configuration accepted")
	}
	invalidIssuer := config
	invalidIssuer.OIDCIssuer = "http://account.example"
	if err := invalidIssuer.Validate(); err == nil {
		t.Fatal("insecure OIDC issuer accepted")
	}
}

func TestTNLDValidateACME(t *testing.T) {
	valid := TNLD{
		Mode: TNLDModeStandalone, StateDir: "/state", Domain: "example.com",
		PublicListen: "127.0.0.1:443", RelayMapFile: "/relay.json", RelayProfile: "default",
		WorkerCapacity: 1, WorkerStreamLimit: 1, PublicConnLimit: 1, RouteConnLimit: 1, DrainTimeout: 30,
		MaxActiveHostnameClaims: 128, MaxHostnameClaimRequests: 1024,
		ACMEDirectoryURL: "https://acme.example/directory", ACMEEmail: "operator@example.com",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid ACME config: %v", err)
	}
	if got := valid.ServerHostname(); got != "tnl.example.com" {
		t.Fatalf("ServerHostname = %q", got)
	}
	if got := valid.RouteSuffix(); got != "apps.example.com" {
		t.Fatalf("RouteSuffix = %q", got)
	}
	provider := valid
	provider.RelayMapFile = ""
	provider.RelayProfile = ""
	provider.RelayProvider = "tailcat"
	if err := provider.Validate(); err != nil {
		t.Fatalf("valid relay provider config: %v", err)
	}
	conflictingRelaySource := provider
	conflictingRelaySource.RelayMapFile = "/relay.json"
	if err := conflictingRelaySource.Validate(); err == nil {
		t.Fatal("relay provider and custom map accepted together")
	}
	missingControlTLS := valid
	missingControlTLS.ACMEDirectoryURL = ""
	missingControlTLS.ACMEEmail = ""
	if err := missingControlTLS.Validate(); err == nil {
		t.Fatal("control config without ACME succeeded")
	}
	for name, mutate := range map[string]func(*TNLD){
		"non-HTTPS directory": func(config *TNLD) { config.ACMEDirectoryURL = "http://acme.example/directory" },
		"invalid email":       func(config *TNLD) { config.ACMEEmail = "Operator <operator@example.com>" },
		"missing ingress":     func(config *TNLD) { config.PublicListen = "" },
		"terms not accepted":  func(config *TNLD) { config.ACMEAcceptTerms = false },
		"invalid domain":      func(config *TNLD) { config.Domain = "Example.com" },
		"long domain":         func(config *TNLD) { config.Domain = strings.Repeat("a.", 95) + "a" },
		"missing relay source": func(config *TNLD) {
			config.RelayMapFile = ""
			config.RelayProfile = ""
		},
		"unknown relay provider": func(config *TNLD) {
			config.RelayMapFile = ""
			config.RelayProfile = ""
			config.RelayProvider = "other"
		},
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
