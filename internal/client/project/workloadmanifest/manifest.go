// package workloadmanifest owns the nonsecret build-to-runtime workload context.
package workloadmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
)

const Filename = "workloads.json"
const MaxBytes = 128 << 10

var ErrInvalid = errors.New("workload manifest is invalid; run tnl generate during the build")
var fingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Acquisition struct {
	Method    string `json:"method"`
	Audience  string `json:"audience,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
}
type Workload struct {
	Provider           string      `json:"provider"`
	Services           []string    `json:"services"`
	MaxDurationSeconds int         `json:"max_duration_seconds"`
	Acquisition        Acquisition `json:"acquisition"`
}
type Manifest struct {
	Schema            int                 `json:"schema"`
	Server            string              `json:"server"`
	Team              string              `json:"team"`
	ProjectKey        string              `json:"project_key"`
	SourceFingerprint string              `json:"source_fingerprint"`
	ProjectLabel      string              `json:"project_label"`
	Workloads         map[string]Workload `json:"workloads"`
	Services          map[string]string   `json:"services"`
}

func Generate(c config.TNL, source projectconfig.SourceIdentity) ([]byte, error) {
	m := Manifest{Schema: 1, Server: clientserver.DefaultURL, ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, ProjectLabel: source.Label, Workloads: map[string]Workload{}, Services: map[string]string{}}
	if c.Server != nil {
		m.Server = *c.Server
	}
	if c.Team != nil {
		m.Team = *c.Team
	}
	var err error
	m.Server, err = clientstate.CanonicalServer(m.Server)
	if err != nil {
		return nil, err
	}
	for name, p := range c.Workloads {
		a := Acquisition{}
		switch p.Provider {
		case "github":
			a.Method = "github-actions"
			a.Audience = m.Server
		case "vercel":
			a.Method = "vercel-oidc"
		case "fly":
			a.Method = "fly-machine-api"
			a.Audience = "https://fly.io/" + p.Org
		case "oidc":
			a.Method = "callback"
			a.Audience = p.Audience
			if p.TokenFile != "" {
				a.Method = "token-file"
				a.TokenFile = p.TokenFile
			}
		}
		services := slices.Clone(p.Services)
		slices.Sort(services)
		m.Workloads[name] = Workload{Provider: p.Provider, Services: services, MaxDurationSeconds: int(p.DurationLimit().Seconds()), Acquisition: a}
		for _, key := range services {
			m.Services[key] = config.Protocol(c.Services[key])
		}
	}
	if err = m.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	return append(b, '\n'), err
}

func (m Manifest) Validate() error {
	server, err := clientstate.CanonicalServer(m.Server)
	if err != nil || server != m.Server || !config.WorkloadHTTPS(m.Server) || m.Schema != 1 || !config.ExactWorkloadValue(m.Team) || !config.ExactWorkloadValue(m.ProjectKey) || !fingerprint.MatchString(m.SourceFingerprint) || !naming.ValidAuthorityLabel(m.ProjectLabel) || len(m.Workloads) == 0 || len(m.Workloads) > 32 || len(m.Services) > 128 {
		return ErrInvalid
	}
	for name, w := range m.Workloads {
		if !naming.ValidServiceName(name) || w.MaxDurationSeconds < 1 || w.MaxDurationSeconds > 21600 || len(w.Services) == 0 || len(w.Services) > 32 {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, s := range w.Services {
			if !naming.ValidServiceName(s) || seen[s] || !slices.Contains([]string{"http", "tcp", "mysql", "postgres", "kubernetes"}, m.Services[s]) {
				return ErrInvalid
			}
			seen[s] = true
		}
		switch w.Provider {
		case "github":
			if w.Acquisition.Method != "github-actions" || w.Acquisition.Audience != m.Server || w.Acquisition.TokenFile != "" {
				return ErrInvalid
			}
		case "vercel":
			if w.Acquisition.Method != "vercel-oidc" || w.Acquisition.TokenFile != "" || w.Acquisition.Audience != "" {
				return ErrInvalid
			}
		case "fly":
			if w.Acquisition.Method != "fly-machine-api" || !config.WorkloadHTTPS(w.Acquisition.Audience) || w.Acquisition.TokenFile != "" {
				return ErrInvalid
			}
		case "oidc":
			if !config.ExactWorkloadValue(w.Acquisition.Audience) || w.Acquisition.Method != "callback" && w.Acquisition.Method != "token-file" || (w.Acquisition.Method == "token-file") != (w.Acquisition.TokenFile != "") {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}

func Read(path string) (m Manifest, err error) {
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return m, err
	}
	if len(b) > MaxBytes {
		return m, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return m, ErrInvalid
	}
	return m, m.Validate()
}
