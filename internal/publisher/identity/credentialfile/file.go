// package credentialfile stores a portable publisher key and its exact grant.
package credentialfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

var ErrInvalid = errors.New("publisher file is missing, unsafe, or invalid; check its owner, permissions, and control URL")
var ErrExists = errors.New("publisher file already exists; choose a new --output-file path")

// File contains only a redeemed grant, never an enrollment key or session.
// private_key is unpadded base64url of the 64-byte Ed25519 private key.
type File struct {
	Version             int     `json:"version"`
	ControlURL          string  `json:"control_url"`
	PublisherIdentityID string  `json:"publisher_identity_id"`
	KeyID               string  `json:"key_id"`
	GrantID             string  `json:"grant_id"`
	TeamID              string  `json:"team_id"`
	Kind                string  `json:"kind"`
	PublicURLID         *string `json:"public_url_id,omitempty"`
	ServiceID           *string `json:"service_id,omitempty"`
	DomainID            *string `json:"domain_id,omitempty"`
	Namespace           *string `json:"namespace,omitempty"`
	PrivateKey          string  `json:"private_key"`
}

func New(server string, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (File, error) {
	f := File{Version: 1, ControlURL: server, PublisherIdentityID: identity.ClientId, KeyID: identity.KeyId, GrantID: identity.GrantId, TeamID: identity.TeamId, Kind: string(identity.Kind), PublicURLID: identity.PublicUrlId, ServiceID: identity.ServiceId, DomainID: identity.DomainId, Namespace: identity.Namespace, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	if _, _, err := f.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}

// Validate returns a complete wire identity and its signing key. a file cannot
// widen its recorded grant or carry a different server in its URL.
func (f File) Validate() (authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, error) {
	server, err := naming.CanonicalControlURL(f.ControlURL)
	if err != nil || server != f.ControlURL || f.Version != 1 {
		return authorityv1.PublisherEnrollmentResult{}, nil, ErrInvalid
	}
	private, err := base64.RawURLEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) || base64.RawURLEncoding.EncodeToString(private) != f.PrivateKey {
		return authorityv1.PublisherEnrollmentResult{}, nil, ErrInvalid
	}
	i := authorityv1.PublisherEnrollmentResult{ClientId: f.PublisherIdentityID, KeyId: f.KeyID, GrantId: f.GrantID, TeamId: f.TeamID, Kind: authorityv1.PublisherEnrollmentResultKind(f.Kind), PublicUrlId: f.PublicURLID, ServiceId: f.ServiceID, DomainId: f.DomainID, Namespace: f.Namespace}
	if !opaqueid.Valid(i.ClientId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(i.KeyId, opaqueid.PublisherIdentityKeyPrefix) || !opaqueid.Valid(i.GrantId, opaqueid.PublisherGrantPrefix) || i.TeamId == "" {
		return i, nil, ErrInvalid
	}
	if i.Kind == "saved_public_url" {
		if i.PublicUrlId == nil || !opaqueid.Valid(*i.PublicUrlId, opaqueid.PublicURLPrefix) || i.DomainId != nil || i.Namespace != nil || i.ServiceId != nil {
			return i, nil, ErrInvalid
		}
	} else if i.Kind == "namespace" {
		if i.PublicUrlId != nil || i.DomainId == nil || !opaqueid.Valid(*i.DomainId, opaqueid.DomainPrefix) || i.Namespace == nil || i.ServiceId != nil {
			return i, nil, ErrInvalid
		}
		canonical, err := naming.CanonicalizeHostname(*i.Namespace)
		if err != nil || canonical != *i.Namespace {
			return i, nil, ErrInvalid
		}
	} else if i.Kind == "service" {
		if i.ServiceId == nil || !opaqueid.Valid(*i.ServiceId, opaqueid.ServicePrefix) || i.PublicUrlId != nil || i.DomainId != nil || i.Namespace != nil {
			return i, nil, ErrInvalid
		}
	} else {
		return i, nil, ErrInvalid
	}
	return i, ed25519.PrivateKey(private), nil
}

// Read pins the directory and file across the read, rejects symlinks and
// permissive modes, and works with a read-only mounted secret.
func Read(path string) (File, error) {
	var result File
	if path == "" {
		return result, ErrInvalid
	}
	parent := filepath.Dir(path)
	dir, err := os.Open(parent)
	if err != nil {
		return result, ErrInvalid
	}
	defer dir.Close()
	beforeDir, err := dir.Stat()
	parentPath, pathErr := os.Lstat(parent)
	if err != nil || pathErr != nil || !beforeDir.IsDir() || !os.SameFile(beforeDir, parentPath) {
		return result, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !safeFile(before) || before.Size() > 8192 {
		return result, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return result, ErrInvalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !safeFile(opened) {
		return result, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	after, statErr := os.Lstat(path)
	afterDir, dirErr := os.Lstat(parent)
	if err != nil || len(data) > 8192 || statErr != nil || dirErr != nil || !os.SameFile(before, after) || !os.SameFile(beforeDir, afterDir) || !safeFile(after) {
		return result, ErrInvalid
	}
	if json.Unmarshal(data, &result, json.RejectUnknownMembers(true)) != nil {
		return File{}, ErrInvalid
	}
	var fields map[string]jsontext.Value
	if json.Unmarshal(data, &fields) != nil {
		return File{}, ErrInvalid
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return File{}, ErrInvalid
		}
	}
	if _, _, err := result.Validate(); err != nil {
		return File{}, ErrInvalid
	}
	return result, nil
}

// Write creates a new file only; retries never replace an existing identity.
// link gives no-clobber publication after the file and its data are synced.
func Write(path string, value File) error {
	if _, _, err := value.Validate(); err != nil || path == "" {
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
	if err != nil {
		return ErrInvalid
	}
	f, err := os.CreateTemp(parent, ".tnl-publisher-*")
	if err != nil {
		return ErrInvalid
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return ErrInvalid
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return ErrInvalid
	}
	if err := f.Sync(); err != nil {
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
	if err := dir.Sync(); err != nil {
		return ErrInvalid
	}
	return nil
}
