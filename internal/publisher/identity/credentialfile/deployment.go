package credentialfile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const maxDeploymentIdentityBytes = 8192

// DeploymentFile is one replica's durable signing identity. runtime databases,
// sessions, enrollment secrets, leases, assignments and targets are excluded.
type DeploymentFile struct {
	Version    int                                   `json:"version"`
	ControlURL string                                `json:"control_url"`
	Instance   string                                `json:"instance"`
	Member     controlv1.DeploymentPublisherIdentity `json:"member"`
	PrivateKey string                                `json:"private_key"`
}

func (DeploymentFile) String() string   { return "deployment identity" }
func (DeploymentFile) GoString() string { return "deployment identity" }

func NewDeployment(server, instance string, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (DeploymentFile, error) {
	f := DeploymentFile{Version: 1, ControlURL: server, Instance: instance, Member: member, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	if _, err := f.Validate(server, member.ProjectKey, member.DeploymentName, instance); err != nil {
		return DeploymentFile{}, err
	}
	return f, nil
}

// Validate checks the explicit deployment scope before any signing or state
// import. control verifies that the key actually belongs to the recorded member.
func (f DeploymentFile) Validate(server, project, deployment, instance string) (ed25519.PrivateKey, error) {
	canonical, err := naming.CanonicalControlURL(f.ControlURL)
	m := f.Member
	if err != nil || canonical != f.ControlURL || f.Version != 1 || f.ControlURL != server ||
		m.ProjectKey != project || f.Instance != instance ||
		!naming.ValidServiceName(m.DeploymentName) || m.DeploymentName == "local" ||
		!naming.ValidProjectKey(m.ProjectKey) || !naming.ValidServiceName(deployment) && !opaqueid.Valid(deployment, "dpl_") || deployment == "local" || !naming.ValidServiceName(instance) ||
		m.TeamId == "" || len(m.TeamId) > 256 || !opaqueid.Valid(m.DeploymentId, "dpl_") ||
		!opaqueid.Valid(m.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(m.KeyId, opaqueid.PublisherIdentityKeyPrefix) {
		return nil, ErrInvalid
	}
	private, err := base64.RawURLEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) || base64.RawURLEncoding.EncodeToString(private) != f.PrivateKey {
		return nil, ErrInvalid
	}
	return ed25519.PrivateKey(private), nil
}

// ParseDeployment accepts the same bounded JSON used by a private file or an ECS
// Secrets Manager injection. errors never retain or echo the supplied JSON.
func ParseDeployment(data []byte) (DeploymentFile, error) {
	var f DeploymentFile
	if len(data) == 0 || len(data) > maxDeploymentIdentityBytes || json.Unmarshal(data, &f, json.RejectUnknownMembers(true)) != nil {
		return DeploymentFile{}, ErrInvalid
	}
	// reject nulls, including inside the member, rather than accepting omitted
	// required fields through JSON's null-to-zero conversions.
	var fields map[string]jsontext.Value
	if json.Unmarshal(data, &fields) != nil {
		return DeploymentFile{}, ErrInvalid
	}
	member := fields["member"]
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return DeploymentFile{}, ErrInvalid
		}
	}
	if json.Unmarshal(member, &fields) != nil {
		return DeploymentFile{}, ErrInvalid
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return DeploymentFile{}, ErrInvalid
		}
	}
	if _, err := f.Validate(f.ControlURL, f.Member.ProjectKey, f.Member.DeploymentName, f.Instance); err != nil {
		return DeploymentFile{}, ErrInvalid
	}
	return f, nil
}

func ReadDeployment(path string) (DeploymentFile, error) {
	parent := filepath.Dir(path)
	dir, err := os.Open(parent)
	if err != nil || path == "" {
		if dir != nil {
			_ = dir.Close()
		}
		return DeploymentFile{}, ErrInvalid
	}
	defer dir.Close()
	beforeDir, err := dir.Stat()
	parentPath, pathErr := os.Lstat(parent)
	if err != nil || pathErr != nil || !beforeDir.IsDir() || !os.SameFile(beforeDir, parentPath) {
		return DeploymentFile{}, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !safeFile(before) || before.Size() > maxDeploymentIdentityBytes {
		return DeploymentFile{}, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return DeploymentFile{}, ErrInvalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !safeFile(opened) {
		return DeploymentFile{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDeploymentIdentityBytes+1))
	after, statErr := os.Lstat(path)
	afterDir, dirErr := os.Lstat(parent)
	if err != nil || statErr != nil || dirErr != nil || !os.SameFile(before, after) || !os.SameFile(beforeDir, afterDir) || !safeFile(after) {
		return DeploymentFile{}, ErrInvalid
	}
	return ParseDeployment(data)
}

// WriteDeployment publishes a synced mode-0600 file without replacing any existing
// path. an interrupted provision can export the same protected key on retry.
func WriteDeployment(path string, value DeploymentFile) error {
	if _, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentName, value.Instance); err != nil || path == "" {
		return ErrInvalid
	}
	parent := filepath.Dir(path)
	dir, err := os.Open(parent)
	if err != nil {
		return ErrInvalid
	}
	defer dir.Close()
	before, err := dir.Stat()
	parentPath, pathErr := os.Lstat(parent)
	if err != nil || pathErr != nil || !before.IsDir() || !os.SameFile(before, parentPath) {
		return ErrInvalid
	}
	if _, err := os.Lstat(path); err == nil {
		return ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalid
	}
	data, err := json.Marshal(value, jsontext.WithIndent("  "))
	if err != nil || len(data)+1 > maxDeploymentIdentityBytes {
		return ErrInvalid
	}
	f, err := os.CreateTemp(parent, ".tnl-deployment-*")
	if err != nil {
		return ErrInvalid
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if f.Chmod(0600) != nil {
		return ErrInvalid
	}
	if _, err := f.Write(append(data, '\n')); err != nil || f.Sync() != nil {
		return ErrInvalid
	}
	after, err := os.Lstat(parent)
	if err != nil || !os.SameFile(before, after) {
		return ErrInvalid
	}
	if err := os.Link(f.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return ErrInvalid
	}
	if dir.Sync() != nil {
		return ErrInvalid
	}
	return nil
}

func DeploymentSelection(project, deployment, instance string) string {
	return "project-publisher:deployment:" + project + ":" + deployment + ":" + instance
}

// ImportDeployment requires the caller's deployment signing-identity lock. it refuses to
// replace a selected identity or a key already installed for the same member.
// call VerifyDeployment with a real control client before importing a fresh secret.
func ImportDeployment(ctx context.Context, profile *clientstate.Store, value DeploymentFile, server, project, deployment, instance string) (ed25519.PrivateKey, error) {
	private, err := value.Validate(server, project, deployment, instance)
	if err != nil {
		return nil, err
	}
	if err := profile.ImportDeploymentIdentity(ctx, value.Member, private, DeploymentSelection(project, value.Member.DeploymentId, instance)); err != nil {
		return nil, err
	}
	return private, nil
}

type DeploymentVerifier interface {
	Verify(context.Context, controlv1.DeploymentPublisherIdentity, ed25519.PrivateKey) (controlv1.DeploymentPublisherVerification, error)
}

// VerifyDeployment proves possession to control and checks its current member scope.
// it uses no person session or enrollment and does not count as a new member.
func VerifyDeployment(ctx context.Context, client DeploymentVerifier, value DeploymentFile, server, project, deployment, instance string) error {
	_, err := ResolveDeployment(ctx, client, value, server, project, deployment, instance)
	return err
}

// ResolveDeployment accepts selectors only from control's current, authenticated
// history. the exported friendly name is descriptive, never an authority check.
func ResolveDeployment(ctx context.Context, client DeploymentVerifier, value DeploymentFile, server, project, deployment, instance string) (DeploymentFile, error) {
	private, err := value.Validate(server, project, deployment, instance)
	if err != nil {
		return DeploymentFile{}, err
	}
	verified, err := client.Verify(ctx, value.Member, private)
	if err != nil {
		return DeploymentFile{}, err
	}
	if !SameDeploymentIdentity(verified.Member, value.Member) || deployment != verified.Member.DeploymentId && !slices.Contains(verified.DeploymentNames, deployment) || !slices.Contains(verified.DeploymentNames, verified.Member.DeploymentName) {
		return DeploymentFile{}, ErrInvalid
	}
	value.Member = verified.Member
	return value, nil
}

func SameDeploymentIdentity(a, b controlv1.DeploymentPublisherIdentity) bool {
	a.DeploymentName = b.DeploymentName
	return a == b
}
