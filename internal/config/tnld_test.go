package config

import (
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestParseTNLD(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "/from-env")
	t.Setenv("TNLD_BACKUP_URL", "s3://backup/tnld")
	t.Setenv("TNLD_DOMAIN", "example.com")
	t.Setenv("TNLD_DNS_SERVER", "127.0.0.1:5353")
	t.Setenv("TNLD_ACME_EMAIL", "operator@example.com")
	t.Setenv("TNLD_ACME_ACCEPT_TERMS", "true")
	t.Setenv("TNLD_RELAY_PROVIDER", "tailcat")

	config, err := ParseTNLD(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.StateDir != "/from-env" {
		t.Fatalf("StateDir = %q, want /from-env", config.StateDir)
	}
	if config.BackupURL != "s3://backup/tnld" {
		t.Fatalf("BackupURL = %q", config.BackupURL)
	}
	if config.Mode != TNLDModeStandalone {
		t.Fatalf("Mode = %q, want %q", config.Mode, TNLDModeStandalone)
	}
	if config.MetricsListen != "127.0.0.1:9090" {
		t.Fatalf("MetricsListen = %q, want 127.0.0.1:9090", config.MetricsListen)
	}
	if config.DNSServer != "127.0.0.1:5353" {
		t.Fatalf("DNSServer = %q, want 127.0.0.1:5353", config.DNSServer)
	}
	if config.PublicListen != ":443" || config.RelayProvider != "tailcat" {
		t.Fatalf("public configuration = %q, %q, want :443, tailcat", config.PublicListen, config.RelayProvider)
	}
	if config.ACMEDirectoryURL != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("ACMEDirectoryURL = %q", config.ACMEDirectoryURL)
	}
	if config.ServerHostname() != "tnl.example.com" || config.HostnameSuffix() != "example.com" {
		t.Fatalf("derived hostnames = %q, %q", config.ServerHostname(), config.HostnameSuffix())
	}
	if config.MaxActiveHostnames != 128 {
		t.Fatalf("MaxActiveHostnames = %d, want 128", config.MaxActiveHostnames)
	}
	if config.MaxHostnameRequests != 1024 {
		t.Fatalf("MaxHostnameRequests = %d, want 1024", config.MaxHostnameRequests)
	}
	if config.AccessTokenLifetime != time.Hour || config.RefreshTokenLifetime != 30*24*time.Hour {
		t.Fatalf("token lifetimes = %s, %s", config.AccessTokenLifetime, config.RefreshTokenLifetime)
	}

	config, err = ParseTNLD([]string{
		"--mode", "edge",
		"--state-dir", "/from-flag",
		"--metrics-listen", "[::1]:9091",
		"--max-active-hostnames", "16",
		"--max-hostname-requests", "32",
		"--worker-token", testWorkerToken(t),
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
	if config.MaxActiveHostnames != 16 || config.MaxHostnameRequests != 32 {
		t.Fatalf("hostname quotas = %d, %d, want 16, 32",
			config.MaxActiveHostnames, config.MaxHostnameRequests)
	}
}

func TestParseTNLDHostnameQuotaEnvironment(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "/state")
	t.Setenv("TNLD_MAX_ACTIVE_HOSTNAMES", "24")
	t.Setenv("TNLD_MAX_HOSTNAME_REQUESTS", "48")

	config, err := ParseTNLD([]string{"--public-listen", ""})
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxActiveHostnames != 24 || config.MaxHostnameRequests != 48 {
		t.Fatalf("hostname quotas = %d, %d, want 24, 48",
			config.MaxActiveHostnames, config.MaxHostnameRequests)
	}
}

func TestParseTNLDAccessTokenLifetimeEnvironment(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "/state")
	t.Setenv("TNLD_ACCESS_TOKEN_LIFETIME", "24h")
	t.Setenv("TNLD_REFRESH_TOKEN_LIFETIME", "240h")

	config, err := ParseTNLD([]string{"--public-listen", ""})
	if err != nil {
		t.Fatal(err)
	}
	if config.AccessTokenLifetime != 24*time.Hour || config.RefreshTokenLifetime != 240*time.Hour {
		t.Fatalf("token lifetimes = %s, %s", config.AccessTokenLifetime, config.RefreshTokenLifetime)
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
	if config.RelayProvider != "" {
		t.Fatalf("RelayProvider = %q, want explicit selection", config.RelayProvider)
	}
}

func TestParseTNLDRejectsInvalidInput(t *testing.T) {
	t.Setenv("TNLD_STATE_DIR", "")

	for name, args := range map[string][]string{
		"empty state directory":       {"--state-dir", "   "},
		"invalid backup URL":          {"--state-dir", "/state", "--backup-url", "file:///backup"},
		"unknown flag":                {"--state-dir", "/state", "--unknown"},
		"unknown mode":                {"--state-dir", "/state", "--mode", "router"},
		"missing metrics port":        {"--state-dir", "/state", "--metrics-listen", "127.0.0.1"},
		"invalid metrics port":        {"--state-dir", "/state", "--metrics-listen", "127.0.0.1:nope"},
		"metrics whitespace":          {"--state-dir", "/state", "--metrics-listen", " 127.0.0.1:9090"},
		"invalid DNS server":          {"--state-dir", "/state", "--dns-server", "127.0.0.1"},
		"zero active hostnames":       {"--state-dir", "/state", "--max-active-hostnames", "0"},
		"negative hostname requests":  {"--state-dir", "/state", "--max-hostname-requests", "-1"},
		"requests below active":       {"--state-dir", "/state", "--max-active-hostnames", "10", "--max-hostname-requests", "9"},
		"active hostnames too large":  {"--state-dir", "/state", "--max-active-hostnames", "100001", "--max-hostname-requests", "100001"},
		"hostname requests too large": {"--state-dir", "/state", "--max-hostname-requests", "100001"},
		"short access lifetime":       {"--state-dir", "/state", "--public-listen", "", "--access-token-lifetime", "4m59s"},
		"long access lifetime":        {"--state-dir", "/state", "--public-listen", "", "--access-token-lifetime", "720h1s"},
		"refresh below access":        {"--state-dir", "/state", "--public-listen", "", "--access-token-lifetime", "2h", "--refresh-token-lifetime", "1h"},
		"long refresh lifetime":       {"--state-dir", "/state", "--public-listen", "", "--refresh-token-lifetime", "8760h1s"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTNLD(args); err == nil {
				t.Fatal("ParseTNLD succeeded")
			}
		})
	}
}

func TestTNLDValidateOIDC(t *testing.T) {
	config, err := ParseTNLD([]string{"--state-dir", "/state", "--public-listen", ""})
	if err != nil {
		t.Fatal(err)
	}
	config.OIDCIssuer = "https://account.example"
	config.OIDCClientID = "tnl-cli"
	config.OIDCLoginFlow = OIDCLoginFlowDeviceCode
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
	invalidFlow := config
	invalidFlow.OIDCLoginFlow = "implicit"
	if err := invalidFlow.Validate(); err == nil {
		t.Fatal("invalid OIDC login flow accepted")
	}
}

func TestTNLDValidateRouteUsage(t *testing.T) {
	config, err := ParseTNLD([]string{"--state-dir", "/state", "--public-listen", ""})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := credentials.NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	config.RouteUsageURL = "https://account.example/reports"
	config.RouteUsageToken = token.String()
	if err := config.Validate(); err != nil {
		t.Fatalf("valid HTTPS route usage configuration: %v", err)
	}

	loopback := config
	loopback.RouteUsageURL = "http://127.0.0.1:8080"
	if err := loopback.Validate(); err != nil {
		t.Fatalf("valid loopback route usage configuration: %v", err)
	}

	for name, mutate := range map[string]func(*TNLD){
		"missing token":   func(config *TNLD) { config.RouteUsageToken = "" },
		"missing URL":     func(config *TNLD) { config.RouteUsageURL = "" },
		"invalid token":   func(config *TNLD) { config.RouteUsageToken = "invalid" },
		"insecure remote": func(config *TNLD) { config.RouteUsageURL = "http://account.example" },
		"URL credentials": func(config *TNLD) { config.RouteUsageURL = "https://user@account.example" },
		"URL query":       func(config *TNLD) { config.RouteUsageURL = "https://account.example?tenant=one" },
		"worker mode":     func(config *TNLD) { config.Mode = TNLDModeWorker },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := config
			mutate(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
		})
	}
}

func TestTNLDValidateACME(t *testing.T) {
	valid := TNLD{
		Mode: TNLDModeStandalone, StateDir: "/state", Domain: "example.com",
		PublicListen: "127.0.0.1:443", RelayMapFile: "/relay.json", RelayRegion: "default",
		WorkerCapacity: 1, WorkerStreamLimit: 1, PublicConnLimit: 1, RouteConnLimit: 1, DrainTimeout: 30,
		MaxActiveHostnames: 128, MaxHostnameRequests: 1024,
		AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 30 * 24 * time.Hour,
		ACMEDirectoryURL: "https://acme.example/directory", ACMEEmail: "operator@example.com",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid ACME config: %v", err)
	}
	if got := valid.ServerHostname(); got != "tnl.example.com" {
		t.Fatalf("ServerHostname = %q", got)
	}
	if got := valid.HostnameSuffix(); got != "example.com" {
		t.Fatalf("HostnameSuffix = %q", got)
	}
	provider := valid
	provider.RelayMapFile = ""
	provider.RelayRegion = ""
	provider.RelayProvider = "tailcat"
	if err := provider.Validate(); err != nil {
		t.Fatalf("valid relay provider config: %v", err)
	}
	conflictingRelaySource := provider
	conflictingRelaySource.RelayMapFile = "/relay.json"
	conflictingRelaySource.RelayRegion = "default"
	if err := conflictingRelaySource.Validate(); err == nil {
		t.Fatal("conflicting relay sources succeeded")
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
			config.RelayRegion = ""
		},
		"unknown relay provider": func(config *TNLD) {
			config.RelayMapFile = ""
			config.RelayRegion = ""
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

func TestTNLDHostnameOverridesAndReservations(t *testing.T) {
	config := TNLD{
		Domain: "example.com", ControlHostname: "control.service.test", PublicHostnameSuffix: "routes.test",
		ReservedRouteNames: []string{"account", "mail"},
	}
	if err := config.validateHostnames(); err != nil {
		t.Fatal(err)
	}
	if config.ServerHostname() != "control.service.test" || config.HostnameSuffix() != "routes.test" {
		t.Fatalf("explicit hostnames = %q, %q", config.ServerHostname(), config.HostnameSuffix())
	}
	reserved := config.EffectiveReservedRouteNames()
	if strings.Join(reserved, ",") != "account,mail,domains" {
		t.Fatalf("reservations = %q", reserved)
	}

	config.ControlHostname = "control.routes.test"
	reserved = config.EffectiveReservedRouteNames()
	if strings.Join(reserved, ",") != "account,mail,domains,control" {
		t.Fatalf("automatic control reservation = %q", reserved)
	}

	for name, names := range map[string][]string{
		"noncanonical": {"Mail"},
		"nested":       {"smtp.mail"},
		"duplicate":    {"mail", "mail"},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := config
			invalid.ReservedRouteNames = names
			if err := invalid.validateHostnames(); err == nil {
				t.Fatal("invalid reservation accepted")
			}
		})
	}
}

func testWorkerToken(t *testing.T) string {
	t.Helper()
	token, _, err := credentials.NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}
	return token.String()
}
