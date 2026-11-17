package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

func TestTNLDControlOutageToleranceFileTypesAndPrecedence(t *testing.T) {
	for _, format := range []struct{ extension, document string }{
		{"yml", "version: 1\ntnld:\n  control_outage_tolerance: 90s\n"},
		{"json", `{"version":1,"tnld":{"control_outage_tolerance":"90s"}}`},
	} {
		t.Run(format.extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl."+format.extension)
			if err := os.WriteFile(path, []byte(format.document), 0o600); err != nil {
				t.Fatal(err)
			}
			document, err := LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			var cfg daemonconfig.Config
			document.TNLD.Apply(&cfg)
			if cfg.ControlOutageTolerance != 90*time.Second {
				t.Fatalf("file tolerance = %v", cfg.ControlOutageTolerance)
			}
			cfg.ControlOutageTolerance = time.Minute
			document.TNLD.ApplyLowerPrecedence(&cfg, map[string]bool{"control_outage_tolerance": true})
			if cfg.ControlOutageTolerance != time.Minute {
				t.Fatal("file replaced flag value")
			}
			t.Setenv("TNLD_CONTROL_OUTAGE_TOLERANCE", "1m")
			document.TNLD.ApplyLowerPrecedence(&cfg, nil)
			if cfg.ControlOutageTolerance != time.Minute {
				t.Fatal("file replaced environment value")
			}
		})
	}
}

func TestTNLDControlOutageToleranceRejectsInvalidFileTypes(t *testing.T) {
	for _, value := range []string{"123", "false", "[5m]", "null", "bad"} {
		t.Run(value, func(t *testing.T) {
			if _, err := loadTNLDYAML(t, "  control_outage_tolerance: "+value+"\n"); err == nil {
				t.Fatal("invalid tolerance accepted")
			}
		})
	}
}
