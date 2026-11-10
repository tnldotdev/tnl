// package credentialfile owns portable native signing credentials. publisher and
// connector operations select explicit grants; this leaf never starts either runtime.
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
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrInvalid = errors.New("credential file is missing, unsafe, or invalid; check its owner, permissions, and control URL")
var ErrExists = errors.New("credential file already exists; choose a new --output-file path")
var ErrGrant = failure.Wrap("select application grant", failure.PublisherGrantMismatch, errors.New("select one exact credential grant for this operation and resource"))
var ErrApplication = failure.Wrap("read application credential", failure.PublisherSelectionInvalid, errors.New("the application signing credential document is invalid"))
var ErrApplicationUnavailable = failure.Wrap("authorize application publication", failure.ServerUnavailable, errors.New("application publication authority is temporarily unavailable"))

const MaxBytes = 65536

// File contains one signing identity and explicit grants, never enrollment keys,
// control sessions, short-lived access tokens, or targets.
// private_key is unpadded base64url of the 64-byte Ed25519 private key.
type File struct {
	Version    int     `json:"version"`
	ControlURL string  `json:"control_url"`
	ClientID   string  `json:"client_id"`
	KeyID      string  `json:"key_id"`
	TeamID     string  `json:"team_id"`
	Grants     []Grant `json:"grants"`
	PrivateKey string  `json:"private_key"`
}

type Grant struct {
	ID          string                         `json:"id"`
	Operation   controlv1.ApplicationOperation `json:"operation"`
	Kind        string                         `json:"kind"`
	PublicURLID *string                        `json:"public_url_id,omitempty"`
	ServiceID   *string                        `json:"service_id,omitempty"`
	DomainID    *string                        `json:"domain_id,omitempty"`
	Namespace   *string                        `json:"namespace,omitempty"`
	ExpiresAt   *time.Time                     `json:"expires_at,omitempty"`
}

func (File) String() string   { return "application signing credential" }
func (File) GoString() string { return "application signing credential" }

// New captures an already prepared publisher in the same explicit-grant format
// used by application registration; there is no single-grant legacy wire shape.
func New(server string, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (File, error) {
	operation := controlv1.ApplicationPublish
	if identity.Kind == authorityv1.Namespace {
		operation = controlv1.ApplicationAllocate
	}
	f := File{Version: 1, ControlURL: server, ClientID: identity.ClientId, KeyID: identity.KeyId, TeamID: identity.TeamId, Grants: []Grant{{ID: identity.GrantId, Operation: operation, Kind: string(identity.Kind), PublicURLID: identity.PublicUrlId, ServiceID: identity.ServiceId, DomainID: identity.DomainId, Namespace: identity.Namespace}}, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	if _, err := f.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}

func NewApplication(server string, application controlv1.RegisteredApplication, private ed25519.PrivateKey) (File, error) {
	grants, err := ApplicationGrants(application)
	if err != nil {
		return File{}, err
	}
	f := File{Version: 1, ControlURL: server, ClientID: application.ClientId, KeyID: application.KeyId, TeamID: application.TeamId, PrivateKey: base64.RawURLEncoding.EncodeToString(private), Grants: grants}
	if _, err := f.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}

// application responses may be empty after narrowing. only a nonempty grant set
// can become a prepared credential; both paths use the same resource validator.
func ApplicationGrants(application controlv1.RegisteredApplication) ([]Grant, error) {
	if !validSigningIdentity(application.ClientId, application.KeyId, application.TeamId) {
		return nil, ErrInvalid
	}
	grants := make([]Grant, 0, len(application.Grants))
	for _, grant := range application.Grants {
		if grant.RevokedAt != nil || grant.TeamId != nil && *grant.TeamId != application.TeamId {
			return nil, ErrInvalid
		}
		grants = append(grants, Grant{ID: grant.Id, Operation: grant.Operation, Kind: string(grant.Kind), PublicURLID: cloneOptional(grant.PublicUrlId), ServiceID: cloneOptional(grant.ServiceId), DomainID: cloneOptional(grant.DomainId), Namespace: cloneOptional(grant.Namespace), ExpiresAt: cloneOptional(grant.ExpiresAt)})
	}
	return grants, validateGrantSet(grants)
}

func cloneOptional[T any](value *T) *T {
	if value == nil {
		return nil
	}
	return new(*value)
}

func validSigningIdentity(client, key, team string) bool {
	return opaqueid.Valid(client, opaqueid.PublisherIdentityPrefix) && opaqueid.Valid(key, opaqueid.PublisherIdentityKeyPrefix) && team != "" && len(team) <= 256
}

// Validate checks the whole document without selecting a default capability.
func (f File) Validate() (ed25519.PrivateKey, error) {
	server, err := naming.CanonicalControlURL(f.ControlURL)
	if err != nil || server != f.ControlURL || f.Version != 1 || len(f.Grants) < 1 || len(f.Grants) > 64 ||
		!validSigningIdentity(f.ClientID, f.KeyID, f.TeamID) {
		return nil, ErrInvalid
	}
	private, err := base64.RawURLEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) || base64.RawURLEncoding.EncodeToString(private) != f.PrivateKey {
		return nil, ErrInvalid
	}
	if err := validateGrantSet(f.Grants); err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(private), nil
}

func validateGrantSet(grants []Grant) error {
	if len(grants) > 64 {
		return ErrInvalid
	}
	ids, bindings := map[string]bool{}, map[string]bool{}
	for _, grant := range grants {
		resource, err := grant.resource()
		if err != nil || ids[grant.ID] || bindings[string(grant.Operation)+":"+resource] {
			return ErrInvalid
		}
		ids[grant.ID], bindings[string(grant.Operation)+":"+resource] = true, true
	}
	return nil
}

func (g Grant) resource() (string, error) {
	i := authorityv1.PublisherEnrollmentResult{Kind: authorityv1.PublisherEnrollmentResultKind(g.Kind), PublicUrlId: g.PublicURLID, ServiceId: g.ServiceID, DomainId: g.DomainID, Namespace: g.Namespace}
	if !opaqueid.Valid(g.ID, opaqueid.PublisherGrantPrefix) || !g.Operation.Valid() || (g.Operation == controlv1.ApplicationAllocate) != (g.Kind == "namespace") || g.ExpiresAt != nil && g.ExpiresAt.IsZero() {
		return "", ErrInvalid
	}
	if i.Kind == "saved_public_url" {
		if i.PublicUrlId == nil || !opaqueid.Valid(*i.PublicUrlId, opaqueid.PublicURLPrefix) || i.DomainId != nil || i.Namespace != nil || i.ServiceId != nil {
			return "", ErrInvalid
		}
		return *i.PublicUrlId, nil
	} else if i.Kind == "namespace" {
		if i.PublicUrlId != nil || i.DomainId == nil || !opaqueid.Valid(*i.DomainId, opaqueid.DomainPrefix) || i.Namespace == nil || i.ServiceId != nil {
			return "", ErrInvalid
		}
		canonical, err := naming.CanonicalizeHostname(*i.Namespace)
		if err != nil || canonical != *i.Namespace {
			return "", ErrInvalid
		}
		return *i.DomainId, nil
	} else if i.Kind == "service" {
		if i.ServiceId == nil || !opaqueid.Valid(*i.ServiceId, opaqueid.ServicePrefix) || i.PublicUrlId != nil || i.DomainId != nil || i.Namespace != nil {
			return "", ErrInvalid
		}
		return *i.ServiceId, nil
	}
	return "", ErrInvalid
}

// Select returns an exact operation/resource binding; an empty resource is only
// usable when that operation has one grant. no fallback changes the operation.
func (f File) Select(operation controlv1.ApplicationOperation, resource string) (Grant, error) {
	if _, err := f.Validate(); err != nil {
		return Grant{}, err
	}
	var selected *Grant
	for _, grant := range f.Grants {
		id, _ := grant.resource()
		if grant.Operation != operation || resource != "" && id != resource {
			continue
		}
		if selected != nil {
			return Grant{}, ErrGrant
		}
		selected = &grant
	}
	if selected == nil {
		return Grant{}, ErrGrant
	}
	return *selected, nil
}

// Publisher selects only publishing or allocation authority. existing native
// publication flows must supply a resource when several such grants are present.
func (f File) Publisher(resource string) (authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, error) {
	key, err := f.Validate()
	if err != nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, err
	}
	var selected *Grant
	for _, grant := range f.Grants {
		id, _ := grant.resource()
		if grant.Operation == controlv1.ApplicationVisit || resource != "" && id != resource {
			continue
		}
		if selected != nil {
			return authorityv1.PublisherEnrollmentResult{}, nil, ErrGrant
		}
		selected = &grant
	}
	if selected == nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, ErrGrant
	}
	return authorityv1.PublisherEnrollmentResult{ClientId: f.ClientID, KeyId: f.KeyID, TeamId: f.TeamID, GrantId: selected.ID, Kind: authorityv1.PublisherEnrollmentResultKind(selected.Kind), PublicUrlId: selected.PublicURLID, ServiceId: selected.ServiceID, DomainId: selected.DomainID, Namespace: selected.Namespace}, key, nil
}

// Parse is shared by file-backed native selection and inline credential sources.
// nulls and duplicate members are rejected, including inside grants.
func Parse(data []byte) (File, error) {
	var result File
	if len(data) == 0 || len(data) > MaxBytes || json.Unmarshal(data, &result, json.RejectUnknownMembers(true)) != nil {
		return File{}, ErrInvalid
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || token.Kind() == 'n' {
			return File{}, ErrInvalid
		}
	}
	if _, err := result.Validate(); err != nil {
		return File{}, err
	}
	return result, nil
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
	if err != nil || !safeFile(before) || before.Size() > MaxBytes {
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
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	defer clear(data)
	after, statErr := os.Lstat(path)
	afterDir, dirErr := os.Lstat(parent)
	if err != nil || len(data) > MaxBytes || statErr != nil || dirErr != nil || !os.SameFile(before, after) || !os.SameFile(beforeDir, afterDir) || !safeFile(after) {
		return result, ErrInvalid
	}
	return Parse(data)
}

// Write creates a new file only; retries never replace an existing identity.
// link gives no-clobber publication after the file and its data are synced.
func Write(path string, value File) error {
	if _, err := value.Validate(); err != nil || path == "" {
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
	if err != nil || len(data) > MaxBytes {
		return ErrInvalid
	}
	f, err := os.CreateTemp(parent, ".tnl-credential-*")
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
