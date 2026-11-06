// package fixture defines the private handoff from the local daemon integration
// topology to the wasm qualification runner. production code must not import it.
package fixture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Config struct {
	Version int `json:"version"`
	// dial the local override while preserving ControlURL's tls and http identity.
	ControlURL         string                    `json:"control_url"`
	ControlDialAddress string                    `json:"control_dial_address"`
	ControlRootPEM     string                    `json:"control_root_pem"`
	RelayRootPEM       string                    `json:"relay_root_pem"`
	ServiceRootPEM     string                    `json:"service_root_pem"`
	TeamID             string                    `json:"team_id"`
	Project            string                    `json:"project"`
	SourceFingerprint  string                    `json:"source_fingerprint"`
	WorkloadPolicy     string                    `json:"workload_policy"`
	Services           map[string]string         `json:"services"`
	ServiceEndpoint    controlv1.ServiceEndpoint `json:"service_endpoint"`
	Relays             []Relay                   `json:"relays"`
	OuterTransport     string                    `json:"outer_transport"`
	FixtureAPIURL      string                    `json:"fixture_api_url"`
	FixtureAPIToken    string                    `json:"fixture_api_token"`
	// all fixture api requests require FixtureAPIToken as a bearer credential.
	// GET AssertionURL?execution=<stable label> returns {token,expires_at}; use
	// the same execution label when refreshing one workload's assertion.
	AssertionURL string `json:"assertion_url"`
	// POST FaultURL with {relay_address,blocked} closes or restores connector
	// outer carriers only. it does not stop publishers or the database target.
	FaultURL                string   `json:"fault_url"`
	ShutdownURL             string   `json:"shutdown_url"`
	NativeConnectorAddress  string   `json:"native_connector_address"`
	NativeWorkloadSessionID string   `json:"native_workload_session_id"`
	Postgres                Postgres `json:"postgres"`
	FaultScope              string   `json:"fault_scope"`
}

type Relay struct {
	// preserve the signed relay identity and tls name while dialing DialAddress.
	RelayAddress  string `json:"relay_address"`
	DialAddress   string `json:"dial_address"`
	TLSServerName string `json:"tls_server_name"`
}

type Postgres struct {
	User          string `json:"user"`
	Password      string `json:"password"`
	Database      string `json:"database"`
	DirectURL     string `json:"direct_url"`
	TLSServerName string `json:"tls_server_name"`
	TargetTLS     bool   `json:"target_tls"`
	// the proof table has (id text PRIMARY KEY,value integer NOT NULL). use a
	// unique id and explicit transaction; neither retries nor ON CONFLICT may
	// hide replay. DirectURL permits an independent application-only observer.
	WriteTable    string `json:"write_table"`
	WriteIDColumn string `json:"write_id_column"`
}

func (Config) String() string     { return "private local connector qualification fixture" }
func (Config) GoString() string   { return "private local connector qualification fixture" }
func (Postgres) String() string   { return "private local PostgreSQL application settings" }
func (Postgres) GoString() string { return "private local PostgreSQL application settings" }

// ValidateFile keeps credential handoffs outside a checkout and in a private
// directory. the integration test defaults to testing.T.TempDir.
func ValidateFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("fixture path must be absolute")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("fixture directory: %w", err)
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("fixture directory must be private (mode 0700)")
	}
	for directory := parent; ; directory = filepath.Dir(directory) {
		if _, err := os.Lstat(filepath.Join(directory, ".git")); err == nil {
			return errors.New("fixture credentials must be outside a checkout")
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixture file must not already exist")
	}
	if strings.ContainsRune(path, '\x00') {
		return errors.New("invalid fixture path")
	}
	return nil
}

func (c Config) WriteFile(path string) error {
	if err := ValidateFile(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".fixture-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	// publish one complete file without replacing an existing path or symlink.
	return os.Link(file.Name(), path)
}
