package config

import "testing"

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

	config, err := ParseTNLD([]string{"--mode", "worker"})
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
