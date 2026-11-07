package workloadmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"

	"github.com/tnldotdev/tnl/internal/naming"
)

var ErrRequired = errors.New("select one saved workload")
var ErrDenied = errors.New("the selected workload does not include this service")

// Runtime contains only selection hints from the application process. authority
// still verifies the acquired assertion against saved trust and service policy.
type Runtime struct {
	Workload        *string `json:"workload,omitempty"`
	Vercel          string  `json:"vercel,omitempty"`
	FlyAppName      string  `json:"fly_app_name,omitempty"`
	GitHubActions   string  `json:"github_actions,omitempty"`
	CloudRunService string  `json:"cloud_run_service,omitempty"`
}

type Selection struct {
	Name      string
	Directory string
	Path      string
	Policy    string
	Manifest  Manifest
	Workload  Workload
}

// Select reads only the generated artifact in the canonical project directory.
// it never evaluates project configuration, Git, provider metadata, or login state.
func Select(directory, configured, service string, runtime Runtime) (Selection, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return Selection{}, ErrInvalid
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return Selection{}, ErrInvalid
	}
	file := filepath.Join(directory, ".tnl", "generated", Filename)
	canonical, err := filepath.EvalSymlinks(file)
	if err != nil || canonical != file {
		return Selection{}, ErrInvalid
	}
	manifest, err := Read(file)
	if err != nil {
		return Selection{}, ErrInvalid
	}
	name := configured
	if runtime.Workload != nil {
		name = *runtime.Workload
		if !naming.ValidServiceName(name) {
			return Selection{}, ErrRequired
		}
	}
	if configured != "" && configured != name {
		return Selection{}, ErrRequired
	}
	if name == "" {
		var providers []string
		if runtime.Vercel == "1" {
			providers = append(providers, "vercel")
		}
		if runtime.FlyAppName != "" {
			providers = append(providers, "fly")
		}
		if runtime.GitHubActions == "true" {
			providers = append(providers, "github")
		}
		if runtime.CloudRunService != "" {
			providers = append(providers, "google")
		}
		if len(providers) != 1 {
			return Selection{}, ErrRequired
		}
		for candidate, workload := range manifest.Workloads {
			if workload.Provider != providers[0] {
				continue
			}
			if name != "" {
				return Selection{}, ErrRequired
			}
			name = candidate
		}
	}
	selected, ok := manifest.Workloads[name]
	if !ok || !naming.ValidServiceName(name) {
		return Selection{}, ErrRequired
	}
	if !naming.ValidServiceName(service) || !slices.Contains(selected.Services, service) {
		return Selection{}, ErrDenied
	}
	data, _ := json.Marshal(manifest)
	digest := sha256.Sum256(data)
	return Selection{Name: name, Directory: directory, Path: file, Policy: hex.EncodeToString(digest[:]), Manifest: manifest, Workload: selected}, nil
}
