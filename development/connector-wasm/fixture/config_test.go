package fixture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateConfigurationHandoff(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "fixture.json")
	config := Config{Version: 1, FixtureAPIToken: "fixture-secret", Postgres: Postgres{Password: "application-secret"}}
	if err := config.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("fixture file is not private", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.FixtureAPIToken != config.FixtureAPIToken || decoded.Postgres.Password != config.Postgres.Password {
		t.Fatal("private configuration did not retain credentials", err)
	}
	if err := config.WriteFile(path); err == nil {
		t.Fatal("replaced an existing credential file")
	}
	for _, value := range []string{fmt.Sprint(config), fmt.Sprintf("%#v", config), fmt.Sprint(config.Postgres), fmt.Sprintf("%#v", config.Postgres)} {
		if strings.Contains(value, "fixture-secret") || strings.Contains(value, "application-secret") {
			t.Fatal("formatted settings exposed credentials")
		}
	}
}

func TestRejectUnsafeConfigurationPaths(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		if err := ValidateFile("fixture.json"); err == nil {
			t.Fatal("accepted relative credential file")
		}
	})
	t.Run("shared directory", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := ValidateFile(filepath.Join(directory, "fixture.json")); err == nil {
			t.Fatal("accepted shared credential directory")
		}
	})
	t.Run("checkout", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, ".git"), []byte("gitdir: elsewhere"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateFile(filepath.Join(directory, "fixture.json")); err == nil {
			t.Fatal("accepted credentials in a checkout")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "fixture.json")
		if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
			t.Fatal(err)
		}
		if err := ValidateFile(path); err == nil {
			t.Fatal("accepted credential symlink")
		}
	})
}
