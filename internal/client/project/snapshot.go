package projectconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const MaxSnapshotBytes = 1 << 20

type projectSnapshot struct {
	Project             Project       `json:"project"`
	PrimaryCheckoutRoot string        `json:"primary_checkout_root"`
	LabelParts          WorktreeLabel `json:"label_parts"`
}

// Snapshot transfers an already evaluated configuration to a native owner. it
// stays in the private process pipe; metadata and journals never contain it.
func (p Project) Snapshot() ([]byte, string, error) {
	parts := p.Worktree.labelParts
	encoded, err := json.Marshal(projectSnapshot{Project: p, PrimaryCheckoutRoot: p.Worktree.PrimaryCheckoutRoot(), LabelParts: WorktreeLabel{Project: parts.project, Checkout: parts.checkout, ID: parts.id}})
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
	return snapshot.Project, nil
}
