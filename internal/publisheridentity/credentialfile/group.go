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

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const maxGroupIdentityBytes = 8192

// GroupFile is one replica's durable signing identity. runtime databases,
// sessions, enrollment secrets, leases, assignments and targets are excluded.
type GroupFile struct {
	Version    int                            `json:"version"`
	ControlURL string                         `json:"control_url"`
	Instance   string                         `json:"instance"`
	Member     controlv1.PublisherGroupMember `json:"member"`
	PrivateKey string                         `json:"private_key"`
}

func (GroupFile) String() string   { return "publisher group identity" }
func (GroupFile) GoString() string { return "publisher group identity" }

func NewGroup(server, instance string, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) (GroupFile, error) {
	f := GroupFile{Version: 1, ControlURL: server, Instance: instance, Member: member, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	if _, err := f.Validate(server, member.ProjectKey, member.GroupName, instance); err != nil {
		return GroupFile{}, err
	}
	return f, nil
}

// Validate checks the explicit deployment scope before any signing or state
// import. control verifies that the key actually belongs to the recorded member.
func (f GroupFile) Validate(server, project, group, instance string) (ed25519.PrivateKey, error) {
	canonical, err := naming.CanonicalControlURL(f.ControlURL)
	m := f.Member
	if err != nil || canonical != f.ControlURL || f.Version != 1 || f.ControlURL != server ||
		m.ProjectKey != project || f.Instance != instance ||
		!naming.ValidServiceName(m.GroupName) || m.GroupName == "local" ||
		!naming.ValidProjectKey(m.ProjectKey) || !naming.ValidServiceName(group) || group == "local" || !naming.ValidServiceName(instance) ||
		m.TeamId == "" || len(m.TeamId) > 256 || !opaqueid.Valid(m.GroupId, "pgrp_") ||
		!opaqueid.Valid(m.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(m.KeyId, opaqueid.PublisherIdentityKeyPrefix) {
		return nil, ErrInvalid
	}
	private, err := base64.RawURLEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) || base64.RawURLEncoding.EncodeToString(private) != f.PrivateKey {
		return nil, ErrInvalid
	}
	return ed25519.PrivateKey(private), nil
}

// ParseGroup accepts the same bounded JSON used by a private file or an ECS
// Secrets Manager injection. errors never retain or echo the supplied JSON.
func ParseGroup(data []byte) (GroupFile, error) {
	var f GroupFile
	if len(data) == 0 || len(data) > maxGroupIdentityBytes || json.Unmarshal(data, &f, json.RejectUnknownMembers(true)) != nil {
		return GroupFile{}, ErrInvalid
	}
	// reject nulls, including inside the member, rather than accepting omitted
	// required fields through JSON's null-to-zero conversions.
	var fields map[string]jsontext.Value
	if json.Unmarshal(data, &fields) != nil {
		return GroupFile{}, ErrInvalid
	}
	member := fields["member"]
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return GroupFile{}, ErrInvalid
		}
	}
	if json.Unmarshal(member, &fields) != nil {
		return GroupFile{}, ErrInvalid
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return GroupFile{}, ErrInvalid
		}
	}
	if _, err := f.Validate(f.ControlURL, f.Member.ProjectKey, f.Member.GroupName, f.Instance); err != nil {
		return GroupFile{}, ErrInvalid
	}
	return f, nil
}

func ReadGroup(path string) (GroupFile, error) {
	parent := filepath.Dir(path)
	dir, err := os.Open(parent)
	if err != nil || path == "" {
		if dir != nil {
			_ = dir.Close()
		}
		return GroupFile{}, ErrInvalid
	}
	defer dir.Close()
	beforeDir, err := dir.Stat()
	parentPath, pathErr := os.Lstat(parent)
	if err != nil || pathErr != nil || !beforeDir.IsDir() || !os.SameFile(beforeDir, parentPath) {
		return GroupFile{}, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !safeFile(before) || before.Size() > maxGroupIdentityBytes {
		return GroupFile{}, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return GroupFile{}, ErrInvalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !safeFile(opened) {
		return GroupFile{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, maxGroupIdentityBytes+1))
	after, statErr := os.Lstat(path)
	afterDir, dirErr := os.Lstat(parent)
	if err != nil || statErr != nil || dirErr != nil || !os.SameFile(before, after) || !os.SameFile(beforeDir, afterDir) || !safeFile(after) {
		return GroupFile{}, ErrInvalid
	}
	return ParseGroup(data)
}

// WriteGroup publishes a synced mode-0600 file without replacing any existing
// path. an interrupted provision can export the same protected key on retry.
func WriteGroup(path string, value GroupFile) error {
	if _, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.GroupName, value.Instance); err != nil || path == "" {
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
	if err != nil || len(data)+1 > maxGroupIdentityBytes {
		return ErrInvalid
	}
	f, err := os.CreateTemp(parent, ".tnl-group-*")
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

func GroupSelection(project, group, instance string) string {
	return "project-publisher:group:" + project + ":" + group + ":" + instance
}

// ImportGroup requires the caller's group signing-identity lock. it refuses to
// replace a selected identity or a key already installed for the same member.
// call VerifyGroup with a real control client before importing a fresh secret.
func ImportGroup(ctx context.Context, profile *clientstate.Store, value GroupFile, server, project, group, instance string) (ed25519.PrivateKey, error) {
	private, err := value.Validate(server, project, group, instance)
	if err != nil {
		return nil, err
	}
	if err := profile.ImportPublisherGroupIdentity(ctx, value.Member, private, GroupSelection(project, value.Member.GroupId, instance)); err != nil {
		return nil, err
	}
	return private, nil
}

type GroupVerifier interface {
	Verify(context.Context, controlv1.PublisherGroupMember, ed25519.PrivateKey) (controlv1.PublisherGroupVerification, error)
}

// VerifyGroup proves possession to control and checks its current member scope.
// it uses no person session or enrollment and does not count as a new member.
func VerifyGroup(ctx context.Context, client GroupVerifier, value GroupFile, server, project, group, instance string) error {
	_, err := ResolveGroup(ctx, client, value, server, project, group, instance)
	return err
}

// ResolveGroup accepts selectors only from control's current, authenticated
// history. the exported friendly name is descriptive, never an authority check.
func ResolveGroup(ctx context.Context, client GroupVerifier, value GroupFile, server, project, group, instance string) (GroupFile, error) {
	private, err := value.Validate(server, project, group, instance)
	if err != nil {
		return GroupFile{}, err
	}
	verified, err := client.Verify(ctx, value.Member, private)
	if err != nil {
		return GroupFile{}, err
	}
	if !SameGroupIdentity(verified.Member, value.Member) || !slices.Contains(verified.GroupNames, group) || !slices.Contains(verified.GroupNames, verified.Member.GroupName) {
		return GroupFile{}, ErrInvalid
	}
	value.Member = verified.Member
	return value, nil
}

func SameGroupIdentity(a, b controlv1.PublisherGroupMember) bool {
	a.GroupName = b.GroupName
	return a == b
}
