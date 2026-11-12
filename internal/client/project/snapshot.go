package project

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/config"
)

const MaxSnapshotBytes = 1 << 20

type projectSnapshot struct {
	Project             Project                             `json:"project"`
	PrimaryCheckoutRoot string                              `json:"primary_checkout_root"`
	LabelParts          WorktreeLabel                       `json:"label_parts"`
	LocalTargets        map[string]config.EnvironmentTarget `json:"local_targets"`
}

// Snapshot transfers an already evaluated configuration to a connector owner. it
// stays in the private process pipe; metadata and journals never contain it.
func (p Project) Snapshot() ([]byte, string, error) {
	parts := p.Worktree.labelParts
	local := make(map[string]config.EnvironmentTarget, len(p.Config.Services))
	for name, service := range p.Config.Services {
		target := config.EnvironmentTarget{Name: service.Name, Access: service.Access, Inspection: service.Inspection, Tunnel: service.Tunnel, HTTP: service.HTTP}
		if value := service.Target; value != nil {
			if value.TLS != nil {
				target.TLS = &config.EnvironmentTargetTLS{Hostname: value.TLS.ServerName, CAFile: value.TLS.CAFile}
			}
			if value.Type == "address" {
				target.Address = value.Address
			} else if value.Type != "app" {
				copy := *value
				copy.TLS = nil
				target.Discovery = &copy
			}
		}
		local[name] = target
	}
	encoded, err := json.Marshal(projectSnapshot{Project: p, PrimaryCheckoutRoot: p.Worktree.PrimaryCheckoutRoot(), LabelParts: WorktreeLabel{Project: parts.project, Checkout: parts.checkout, ID: parts.id}, LocalTargets: local})
	if err != nil {
		return nil, "", err
	}
	if len(encoded) > MaxSnapshotBytes {
		return nil, "", errors.New("selected project snapshot exceeds 1 MiB")
	}
	digest := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(digest[:]), nil
}

func ReadSnapshot(input io.Reader) (Project, error) {
	var snapshot projectSnapshot
	encoded, err := io.ReadAll(io.LimitReader(input, MaxSnapshotBytes+1))
	if err != nil || len(encoded) > MaxSnapshotBytes {
		return Project{}, errors.New("cannot read selected project snapshot")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return Project{}, errors.New("selected project snapshot is invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Project{}, errors.New("selected project snapshot has trailing data")
	}
	snapshot.Project.Worktree.primaryRoot = snapshot.PrimaryCheckoutRoot
	snapshot.Project.Worktree.labelParts = worktreeLabelParts{project: snapshot.LabelParts.Project, checkout: snapshot.LabelParts.Checkout, id: snapshot.LabelParts.ID}
	for name, target := range snapshot.LocalTargets {
		service, found := snapshot.Project.Config.Services[name]
		if !found {
			return Project{}, errors.New("selected project snapshot names an unknown local service")
		}
		snapshot.Project.Config.Services[name] = target.Service(service.Protocol)
	}
	return snapshot.Project, nil
}
