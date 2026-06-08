package config

import (
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

	config, err = ParseTNLD([]string{
		"--mode", "edge",
		"--state-dir", "/from-flag",
		"--metrics-listen", "[::1]:9091",
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
		"--relay-map-file", "/relay.json",
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
		"missing state directory": nil,
		"empty state directory":   {"--state-dir", "   "},
		"unknown flag":            {"--state-dir", "/state", "--unknown"},
		"unknown mode":            {"--state-dir", "/state", "--mode", "router"},
		"missing metrics port":    {"--state-dir", "/state", "--metrics-listen", "127.0.0.1"},
		"invalid metrics port":    {"--state-dir", "/state", "--metrics-listen", "127.0.0.1:nope"},
		"metrics whitespace":      {"--state-dir", "/state", "--metrics-listen", " 127.0.0.1:9090"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTNLD(args); err == nil {
				t.Fatal("ParseTNLD succeeded")
			}
		})
	}
}

func TestTNLDValidateACME(t *testing.T) {
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	valid := TNLD{
		Mode: TNLDModeStandalone, StateDir: "/state", ControlListen: "127.0.0.1:8443",
		PublicListen: "127.0.0.1:443", ControlCertFile: "/control.crt", ControlKeyFile: "/control.key",
		BootstrapToken: bootstrap.String(), RelayMapFile: "/relay.json", RelayProfile: "default",
		WorkerCapacity: 1, WorkerStreamLimit: 1, PublicConnLimit: 1, RouteConnLimit: 1, DrainTimeout: 30,
		ACMEDirectoryURL: "https://acme.example/directory", ACMEEmail: "operator@example.com", ACMEProfile: "tlsserver",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid ACME config: %v", err)
	}
	for name, mutate := range map[string]func(*TNLD){
		"non-HTTPS directory": func(config *TNLD) { config.ACMEDirectoryURL = "http://acme.example/directory" },
		"invalid email":       func(config *TNLD) { config.ACMEEmail = "Operator <operator@example.com>" },
		"missing ingress":     func(config *TNLD) { config.PublicListen = "" },
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
