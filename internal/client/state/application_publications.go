package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// ApplicationPublicationCapacity is the existing per-project app owner bound.
const ApplicationPublicationCapacity = 256
const ApplicationPublicationLeaseDuration = 20 * time.Second

const maxApplicationPublicationBytes = 64 << 10

var ErrApplicationPublicationUncertain = errors.New("application publication durable outcome is uncertain")
var ErrApplicationConfirmationExpired = errors.New("application publication confirmation deadline passed")

type ApplicationPublicationPhase string

const (
	ApplicationExchangePending   ApplicationPublicationPhase = "exchange_pending"
	ApplicationSessionAccepted   ApplicationPublicationPhase = "session_accepted"
	ApplicationAllocationPending ApplicationPublicationPhase = "allocation_pending"
	ApplicationURLAccepted       ApplicationPublicationPhase = "url_accepted"
	ApplicationRefreshPending    ApplicationPublicationPhase = "refresh_pending"
	ApplicationDenied            ApplicationPublicationPhase = "denied"
	ApplicationCleanupPending    ApplicationPublicationPhase = "cleanup_pending"
	ApplicationCleanupDone       ApplicationPublicationPhase = "cleanup_done"
)

// ApplicationPublicationBinding contains native-validated public request facts.
// owner is a digest of the SDK's stable secret, not its PID or HTTP capability.
// transient assertions and claims derived from them are deliberately absent.
type ApplicationPublicationBinding struct {
	ServerURL           string `json:"server_url"`
	InvocationID        string `json:"invocation_id"`
	OwnerHash           string `json:"owner_hash"`
	PID                 int    `json:"pid"`
	Target              string `json:"target"`
	ConfigurationDigest string `json:"configuration_digest"`
	RequestDigest       string `json:"request_digest"`
	ResourceID          string `json:"resource_id,omitempty"`
	Namespace           string `json:"namespace,omitempty"`
	SourceKind          string `json:"source_kind"`
	SourceMachineID     string `json:"source_machine_id"`
	SourceKeyID         string `json:"source_key_id,omitempty"`
}

type ApplicationPublicationRecord struct {
	Version              int                                    `json:"version"`
	Revision             uint64                                 `json:"revision"`
	StateRoot            string                                 `json:"state_root"`
	ProjectRoot          string                                 `json:"project_root"`
	WorktreeRoot         string                                 `json:"worktree_root"`
	Binding              ApplicationPublicationBinding          `json:"binding"`
	Phase                ApplicationPublicationPhase            `json:"phase"`
	ResumePhase          ApplicationPublicationPhase            `json:"resume_phase,omitempty"`
	NativeKey            []byte                                 `json:"native_key,omitempty"`
	Nonce                string                                 `json:"nonce,omitempty"`
	SessionID            string                                 `json:"session_id,omitempty"`
	Publisher            *authorityv1.PublisherEnrollmentResult `json:"publisher,omitempty"`
	AccessExpiresAt      time.Time                              `json:"access_expires_at,omitempty"`
	IdentityExpiresAt    time.Time                              `json:"identity_expires_at,omitempty"`
	RenewAfter           time.Time                              `json:"renew_after,omitempty"`
	OwnerExpiresAt       time.Time                              `json:"owner_expires_at"`
	PublicURL            *controlv1.PublicURL                   `json:"public_url,omitempty"`
	ConfirmationDeadline time.Time                              `json:"confirmation_deadline,omitempty"`
	ConfirmedAt          time.Time                              `json:"confirmed_at,omitempty"`
}

// confirmationPending never authorizes an extended lease. its original deadline
// remains fixed across an uncertain write, reopen, and exact-tuple recovery.
func (r ApplicationPublicationRecord) ConfirmationPending() bool {
	return !r.ConfirmationDeadline.IsZero() && r.ConfirmedAt.IsZero()
}

func (ApplicationPublicationRecord) String() string {
	return "protected application publication record"
}
func (ApplicationPublicationRecord) GoString() string {
	return "protected application publication record"
}

// ApplicationPublications owns one canonical project's checkpoint files and
// exclusive native-process lock. it knows no publisher runtime or HTTP handler.
type ApplicationPublications struct {
	files                                *PrivateDirectory
	stateRoot, projectRoot, worktreeRoot string
	configured                           int
	owner                                *Lock
	ownerPin                             os.FileInfo
	mu                                   sync.Mutex
	closed                               bool
}

type ApplicationPublication struct {
	owner   *ApplicationPublications
	binding ApplicationPublicationBinding
	name    string
}

func OpenApplicationPublications(stateRoot, projectRoot, worktreeRoot string, configured int) (*ApplicationPublications, error) {
	if configured < 0 || configured > ApplicationPublicationCapacity {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	paths := []*string{&stateRoot, &projectRoot, &worktreeRoot}
	for _, path := range paths {
		canonical, err := filepath.EvalSymlinks(*path)
		if err != nil || !filepath.IsAbs(*path) || canonical != *path {
			return nil, identityFileError(ErrPublisherStateConflict)
		}
	}
	root, err := OpenPrivateDirectory(filepath.Join(stateRoot, "identities"))
	if err != nil {
		return nil, err
	}
	scope, _ := json.Marshal([]string{"application-publications/v1", stateRoot, projectRoot, worktreeRoot})
	files, err := root.Scoped(string(scope))
	if err != nil {
		return nil, err
	}
	lock, err := openLock(filepath.Join(files.Path(), "owner.lock"), "application publication owner")
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filepath.Join(files.Path(), "owner.lock"))
	if err == nil {
		err = validatePrivateFile(info, false)
	}
	if err == nil {
		err = files.validate()
	}
	if err != nil {
		return nil, errors.Join(identityFileError(err), lock.Close())
	}
	return &ApplicationPublications{files: files, owner: lock, ownerPin: info, stateRoot: stateRoot, projectRoot: projectRoot, worktreeRoot: worktreeRoot, configured: configured}, nil
}

func (p *ApplicationPublications) validateOwner() error {
	info, err := os.Lstat(filepath.Join(p.files.Path(), "owner.lock"))
	if err == nil {
		err = validatePrivateFile(info, false)
	}
	if err == nil && !os.SameFile(p.ownerPin, info) {
		err = ErrPublisherStateConflict
	}
	return identityFileError(err)
}

func (p *ApplicationPublications) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.owner.Close()
}

func validApplicationDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validApplicationBinding(b ApplicationPublicationBinding) bool {
	server, err := CanonicalServer(b.ServerURL)
	if err != nil || server != b.ServerURL || !opaqueid.Valid(b.InvocationID, opaqueid.InvocationPrefix) || !validApplicationDigest(b.OwnerHash) || !validApplicationDigest(b.ConfigurationDigest) || !validApplicationDigest(b.RequestDigest) || b.PID <= 0 || b.Target == "" || len(b.Target) > 4096 || !machineproof.ValidSource(authorityv1.IdentitySourceSelection{Kind: authorityv1.IdentitySourceSelectionKind(b.SourceKind), MachineId: b.SourceMachineID, KeyId: b.SourceKeyID}) || (b.ResourceID == "") == (b.Namespace == "") {
		return false
	}
	if b.ResourceID != "" {
		return opaqueid.Valid(b.ResourceID, opaqueid.PublicURLPrefix)
	}
	namespace, err := naming.CanonicalizeHostname(b.Namespace)
	return err == nil && namespace == b.Namespace
}

func applicationPublicationName(server, invocation string) string {
	encoded, _ := json.Marshal([]string{server, invocation})
	digest := sha256.Sum256(encoded)
	return "publication-" + hex.EncodeToString(digest[:]) + ".json"
}

// Publication compares immutable owner/request facts before returning existing
// key material. different facts must never create a second file for the tuple.
func (p *ApplicationPublications) Publication(ctx context.Context, binding ApplicationPublicationBinding, ownerExpiresAt time.Time) (*ApplicationPublication, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !validApplicationBinding(binding) || !ownerExpiresAt.After(time.Now()) {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	entry := &ApplicationPublication{owner: p, binding: binding, name: applicationPublicationName(binding.ServerURL, binding.InvocationID)}
	existing, found, err := entry.read(true)
	clear(existing.NativeKey)
	if err = errors.Join(context.Cause(ctx), err); err != nil {
		return nil, err
	}
	if found {
		return entry, nil
	}
	records, err := p.records()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, record := range records {
			clear(record.NativeKey)
		}
	}()
	live := p.configured
	for _, record := range records {
		clear(record.NativeKey)
		if record.Binding.InvocationID == binding.InvocationID {
			return nil, identityFileError(ErrPublisherStateConflict)
		}
		if record.Phase != ApplicationCleanupDone {
			live++
		}
	}
	if live >= ApplicationPublicationCapacity || len(records) >= 2*ApplicationPublicationCapacity {
		return nil, identityFileError(errors.New("local publisher service capacity reached"))
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	record := ApplicationPublicationRecord{Version: 1, Revision: 1, StateRoot: p.stateRoot, ProjectRoot: p.projectRoot, WorktreeRoot: p.worktreeRoot, Binding: binding, Phase: ApplicationExchangePending, NativeKey: key, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), OwnerExpiresAt: ownerExpiresAt}
	if err := entry.write(record); err != nil {
		return nil, errors.Join(ErrApplicationPublicationUncertain, context.Cause(ctx), err)
	}
	if err := context.Cause(ctx); err != nil {
		return nil, errors.Join(ErrApplicationPublicationUncertain, err)
	}
	return entry, nil
}

func (r *ApplicationPublication) read(sync bool) (ApplicationPublicationRecord, bool, error) {
	if err := r.owner.validateOwner(); err != nil {
		return ApplicationPublicationRecord{}, false, err
	}
	data, found, err := r.owner.files.Read(r.name, maxApplicationPublicationBytes)
	defer clear(data)
	if err != nil || !found {
		return ApplicationPublicationRecord{}, found, err
	}
	var record ApplicationPublicationRecord
	if json.Unmarshal(data, &record, json.RejectUnknownMembers(true)) != nil || r.owner.validate(record) != nil || record.Binding != r.binding || applicationPublicationName(record.Binding.ServerURL, record.Binding.InvocationID) != r.name {
		clear(record.NativeKey)
		return ApplicationPublicationRecord{}, true, identityFileError(ErrPublisherStateConflict)
	}
	if sync {
		if err := r.owner.files.Sync(r.name); err != nil {
			clear(record.NativeKey)
			return ApplicationPublicationRecord{}, true, err
		}
	}
	return record, true, nil
}

func (p *ApplicationPublications) validate(r ApplicationPublicationRecord) error {
	if r.Version != 1 || r.Revision == 0 || r.StateRoot != p.stateRoot || r.ProjectRoot != p.projectRoot || r.WorktreeRoot != p.worktreeRoot || !validApplicationBinding(r.Binding) || r.OwnerExpiresAt.IsZero() {
		return ErrPublisherStateConflict
	}
	if r.ConfirmationDeadline.IsZero() && !r.ConfirmedAt.IsZero() || !r.ConfirmedAt.IsZero() && !r.ConfirmedAt.Before(r.ConfirmationDeadline) {
		return ErrPublisherStateConflict
	}
	if r.Phase == ApplicationCleanupDone {
		if len(r.NativeKey) != 0 {
			return ErrPublisherStateConflict
		}
	} else if len(r.NativeKey) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(r.NativeKey[:32]).Equal(ed25519.PrivateKey(r.NativeKey)) {
		return ErrPublisherStateConflict
	}
	if !workloadproof.ValidNonce(r.Nonce) {
		return ErrPublisherStateConflict
	}
	switch r.Phase {
	case ApplicationExchangePending, ApplicationSessionAccepted, ApplicationAllocationPending, ApplicationURLAccepted, ApplicationRefreshPending, ApplicationDenied, ApplicationCleanupPending, ApplicationCleanupDone:
	default:
		return ErrPublisherStateConflict
	}
	if r.Publisher != nil {
		v := r.Publisher
		if !opaqueid.Valid(r.SessionID, "mps_") || !opaqueid.Valid(v.ClientId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(v.KeyId, opaqueid.PublisherIdentityKeyPrefix) || !opaqueid.Valid(v.GrantId, opaqueid.PublisherGrantPrefix) || !opaqueid.Valid(v.TeamId, opaqueid.TeamPrefix) || r.IdentityExpiresAt.IsZero() || r.AccessExpiresAt.IsZero() || r.AccessExpiresAt.After(r.IdentityExpiresAt) || r.RenewAfter.IsZero() || !r.RenewAfter.Before(r.AccessExpiresAt) {
			return ErrPublisherStateConflict
		}
		if r.Binding.ResourceID != "" && (v.Kind != authorityv1.SavedPublicUrl || v.PublicUrlId == nil || *v.PublicUrlId != r.Binding.ResourceID || v.Namespace != nil || v.DomainId != nil || v.ServiceId != nil) {
			return ErrPublisherStateConflict
		}
		if r.Binding.Namespace != "" && (v.Kind != authorityv1.Namespace || v.Namespace == nil || *v.Namespace != r.Binding.Namespace || v.DomainId == nil || !opaqueid.Valid(*v.DomainId, opaqueid.DomainPrefix) || v.PublicUrlId != nil || v.ServiceId != nil) {
			return ErrPublisherStateConflict
		}
	} else if r.Phase != ApplicationExchangePending && r.Phase != ApplicationDenied && r.Phase != ApplicationCleanupPending && r.Phase != ApplicationCleanupDone {
		return ErrPublisherStateConflict
	}
	if r.Phase == ApplicationExchangePending && (r.Publisher != nil || r.SessionID != "") {
		return ErrPublisherStateConflict
	}
	if r.PublicURL != nil {
		u := r.PublicURL
		if r.Publisher == nil || !opaqueid.Valid(u.Id, opaqueid.PublicURLPrefix) || u.TeamId != r.Publisher.TeamId || u.Purpose != controlv1.App || u.ServiceProtocol != controlv1.Http || u.LifecycleState != controlv1.Enabled || u.PublisherPool != nil && *u.PublisherPool {
			return ErrPublisherStateConflict
		}
		if r.Binding.ResourceID != "" && (u.Id != r.Binding.ResourceID || u.Ephemeral) {
			return ErrPublisherStateConflict
		}
		if r.Binding.Namespace != "" && (!u.Ephemeral || u.Target != r.Binding.Target || u.DomainId != *r.Publisher.DomainId || !strings.HasSuffix(u.CanonicalHostname, "."+r.Binding.Namespace)) {
			return ErrPublisherStateConflict
		}
	}
	if r.Phase == ApplicationURLAccepted && r.PublicURL == nil || r.Phase == ApplicationRefreshPending && r.ResumePhase != ApplicationSessionAccepted && r.ResumePhase != ApplicationAllocationPending && r.ResumePhase != ApplicationURLAccepted {
		return ErrPublisherStateConflict
	}
	return nil
}

func (r *ApplicationPublication) write(record ApplicationPublicationRecord) error {
	if err := r.owner.validateOwner(); err != nil {
		return err
	}
	if err := r.owner.validate(record); err != nil {
		return identityFileError(err)
	}
	data, err := json.Marshal(record)
	defer clear(data)
	if err != nil || len(data) > maxApplicationPublicationBytes {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.owner.files.Write(r.name, data)
}

func (r *ApplicationPublication) Snapshot(ctx context.Context) (ApplicationPublicationRecord, error) {
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return ApplicationPublicationRecord{}, err
	}
	if r.owner.closed {
		return ApplicationPublicationRecord{}, identityFileError(ErrPublisherStateConflict)
	}
	record, found, err := r.read(true)
	if err == nil && !found {
		err = identityFileError(ErrPublisherStateConflict)
	}
	err = errors.Join(context.Cause(ctx), err)
	if err != nil {
		clear(record.NativeKey)
		return ApplicationPublicationRecord{}, err
	}
	return record, nil
}

func (r *ApplicationPublication) Checkpoint(ctx context.Context, next ApplicationPublicationRecord) error {
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if r.owner.closed {
		return identityFileError(ErrPublisherStateConflict)
	}
	previous, found, err := r.read(true)
	defer clear(previous.NativeKey)
	if err = errors.Join(context.Cause(ctx), err); err != nil {
		return err
	}
	if !found || previous.Revision != next.Revision || previous.Binding != next.Binding || previous.Nonce != next.Nonce || previous.Phase == ApplicationCleanupDone || next.Phase != ApplicationCleanupDone && !slices.Equal(previous.NativeKey, next.NativeKey) {
		return identityFileError(ErrPublisherStateConflict)
	}
	if previous.Publisher != nil {
		before, _ := json.Marshal(previous.Publisher)
		after, _ := json.Marshal(next.Publisher)
		if !slices.Equal(before, after) || previous.SessionID != next.SessionID {
			return identityFileError(ErrPublisherStateConflict)
		}
	}
	if previous.PublicURL != nil {
		before, _ := json.Marshal(previous.PublicURL)
		after, _ := json.Marshal(next.PublicURL)
		if !slices.Equal(before, after) {
			return identityFileError(ErrPublisherStateConflict)
		}
	}
	terminal := next.Phase == ApplicationCleanupPending || next.Phase == ApplicationCleanupDone || next.Phase == ApplicationDenied
	if !applicationCheckpointTransition(previous.Phase, next.Phase) && !(previous.ConfirmationPending() && next.Phase == previous.Phase) {
		return identityFileError(ErrPublisherStateConflict)
	}
	if previous.Phase == ApplicationRefreshPending && next.Phase != ApplicationCleanupPending && next.Phase != ApplicationDenied && next.Phase != previous.ResumePhase {
		return identityFileError(ErrPublisherStateConflict)
	}
	if next.Phase != ApplicationRefreshPending && next.Phase != ApplicationCleanupPending && next.Phase != ApplicationCleanupDone && (next.IdentityExpiresAt.Before(previous.IdentityExpiresAt) || next.AccessExpiresAt.Before(previous.AccessExpiresAt)) {
		return identityFileError(ErrPublisherStateConflict)
	}
	next.Revision++
	if previous.ConfirmationPending() && !terminal && previous.Phase != next.Phase {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.writeCheckpoint(ctx, previous, next)
}

func applicationConfirmationDeadline(ctx context.Context, previous ApplicationPublicationRecord) time.Time {
	deadline := previous.OwnerExpiresAt
	if previous.Publisher != nil && previous.IdentityExpiresAt.Before(deadline) {
		deadline = previous.IdentityExpiresAt
	}
	if previous.ConfirmationPending() && previous.ConfirmationDeadline.Before(deadline) {
		deadline = previous.ConfirmationDeadline
	}
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

// a new lease is written as an unconfirmed candidate first. only a complete
// candidate sync observed before the original deadline can receive a receipt.
// the receipt records that prior durability event, not a guessed pre-write time.
func (r *ApplicationPublication) writeCheckpoint(ctx context.Context, previous, next ApplicationPublicationRecord) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	terminal := next.Phase == ApplicationCleanupPending || next.Phase == ApplicationCleanupDone || next.Phase == ApplicationDenied
	extends := !terminal && (previous.ConfirmationPending() || previous.Publisher == nil && next.Publisher != nil || next.OwnerExpiresAt.After(previous.OwnerExpiresAt) || next.IdentityExpiresAt.After(previous.IdentityExpiresAt) || next.AccessExpiresAt.After(previous.AccessExpiresAt))
	next.ConfirmationDeadline, next.ConfirmedAt = previous.ConfirmationDeadline, previous.ConfirmedAt
	if terminal {
		next.ConfirmationDeadline, next.ConfirmedAt = time.Time{}, time.Time{}
	}
	if extends {
		deadline := applicationConfirmationDeadline(ctx, previous)
		if !time.Now().Before(deadline) {
			return errors.Join(ErrApplicationPublicationUncertain, context.Cause(ctx), ErrApplicationConfirmationExpired)
		}
		next.ConfirmationDeadline, next.ConfirmedAt = deadline, time.Time{}
	}
	writeErr := r.write(next)
	if err := errors.Join(context.Cause(ctx), writeErr); err != nil {
		return errors.Join(ErrApplicationPublicationUncertain, err)
	}
	if !extends {
		return nil
	}
	confirmedAt := time.Now()
	if !confirmedAt.Before(next.ConfirmationDeadline) {
		return errors.Join(ErrApplicationPublicationUncertain, ErrApplicationConfirmationExpired)
	}
	next.ConfirmedAt = confirmedAt
	writeErr = r.write(next)
	if err := errors.Join(context.Cause(ctx), writeErr); err != nil {
		return errors.Join(ErrApplicationPublicationUncertain, err)
	}
	if !time.Now().Before(next.ConfirmationDeadline) {
		return errors.Join(ErrApplicationPublicationUncertain, ErrApplicationConfirmationExpired)
	}
	return nil
}

func (p *ApplicationPublications) records() ([]ApplicationPublicationRecord, error) {
	if err := p.validateOwner(); err != nil {
		return nil, err
	}
	root, err := p.files.open()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, identityFileError(err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2*ApplicationPublicationCapacity + 3)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, identityFileError(err)
	}
	if len(entries) == 2*ApplicationPublicationCapacity+3 {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	var records []ApplicationPublicationRecord
	success := false
	defer func() {
		if !success {
			for _, record := range records {
				clear(record.NativeKey)
			}
		}
	}()
	for _, file := range entries {
		name := file.Name()
		// only this exclusively locked owner writes within the scope. an atomic
		// write's orphaned temporary file is never a second recovery authority.
		if suffix, temporary := strings.CutPrefix(name, ".identity-"); temporary {
			nonce, err := hex.DecodeString(suffix)
			if err != nil || len(nonce) != 16 || suffix != strings.ToLower(suffix) {
				return nil, identityFileError(ErrPublisherStateConflict)
			}
			if err := p.files.Remove(name); err != nil {
				return nil, err
			}
			continue
		}
		if !strings.HasPrefix(name, "publication-") || !strings.HasSuffix(name, ".json") {
			if name != "owner.lock" {
				return nil, identityFileError(ErrPublisherStateConflict)
			}
			continue
		}
		data, found, err := p.files.Read(name, maxApplicationPublicationBytes)
		var record ApplicationPublicationRecord
		if err == nil && (!found || json.Unmarshal(data, &record, json.RejectUnknownMembers(true)) != nil || p.validate(record) != nil || applicationPublicationName(record.Binding.ServerURL, record.Binding.InvocationID) != name) {
			err = identityFileError(ErrPublisherStateConflict)
		}
		clear(data)
		if err != nil {
			clear(record.NativeKey)
			return nil, err
		}
		records = append(records, record)
		if len(records) > 2*ApplicationPublicationCapacity {
			return nil, identityFileError(ErrPublisherStateConflict)
		}
	}
	success = true
	return records, nil
}

// Pending returns only checkpoint references; no credential enters observations.
// existing entries remain accessible for cleanup even at creation capacity.
func (p *ApplicationPublications) Pending(ctx context.Context) ([]*ApplicationPublication, error) {
	return p.entries(ctx, false)
}

// Entries includes completed tombstones so the native owner can retire those
// whose app has exited. pending obligations are never evicted for capacity.
func (p *ApplicationPublications) Entries(ctx context.Context) ([]*ApplicationPublication, error) {
	return p.entries(ctx, true)
}

func (p *ApplicationPublications) entries(ctx context.Context, completed bool) ([]*ApplicationPublication, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if p.closed {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	records, err := p.records()
	if err != nil {
		return nil, err
	}
	if cause := context.Cause(ctx); cause != nil {
		for _, record := range records {
			clear(record.NativeKey)
		}
		return nil, cause
	}
	var result []*ApplicationPublication
	for _, record := range records {
		clear(record.NativeKey)
		if completed || record.Phase != ApplicationCleanupDone {
			result = append(result, &ApplicationPublication{owner: p, binding: record.Binding, name: applicationPublicationName(record.Binding.ServerURL, record.Binding.InvocationID)})
		}
	}
	return result, nil
}

// RemoveCompleted follows a durable cleanup acknowledgment. removal errors are
// uncertain outcomes, never permission to recreate an invocation with a new key.
func (r *ApplicationPublication) RemoveCompleted(ctx context.Context) error {
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if r.owner.closed {
		return identityFileError(ErrPublisherStateConflict)
	}
	record, found, err := r.read(true)
	defer clear(record.NativeKey)
	if err = errors.Join(context.Cause(ctx), err); err != nil {
		return err
	}
	if found && record.Phase != ApplicationCleanupDone {
		return identityFileError(ErrPublisherStateConflict)
	}
	removeErr := r.owner.files.Remove(r.name)
	if err := errors.Join(context.Cause(ctx), removeErr); err != nil {
		return errors.Join(ErrApplicationPublicationUncertain, err)
	}
	return nil
}

func applicationCheckpointTransition(before, after ApplicationPublicationPhase) bool {
	if before == ApplicationCleanupDone {
		return false
	}
	if after == ApplicationCleanupPending {
		return true
	}
	if after == ApplicationDenied {
		return before != ApplicationCleanupPending
	}
	switch before {
	case ApplicationExchangePending:
		return after == ApplicationSessionAccepted
	case ApplicationSessionAccepted:
		return after == ApplicationAllocationPending || after == ApplicationURLAccepted || after == ApplicationRefreshPending
	case ApplicationAllocationPending:
		return after == ApplicationURLAccepted || after == ApplicationRefreshPending
	case ApplicationURLAccepted:
		return after == ApplicationRefreshPending
	case ApplicationRefreshPending:
		return after == ApplicationSessionAccepted || after == ApplicationAllocationPending || after == ApplicationURLAccepted
	case ApplicationCleanupPending, ApplicationDenied:
		return after == ApplicationCleanupDone
	}
	return false
}

func (r *ApplicationPublication) Binding() ApplicationPublicationBinding { return r.binding }

// ForgetCompleted retires records only after the authenticated capability is
// released. a still-pending obligation prevents that release.
func (p *ApplicationPublications) ForgetCompleted(ctx context.Context, invocation string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if p.closed {
		return identityFileError(ErrPublisherStateConflict)
	}
	records, err := p.records()
	if err != nil {
		return err
	}
	defer func() {
		for _, record := range records {
			clear(record.NativeKey)
		}
	}()
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	for _, record := range records {
		if record.Binding.InvocationID != invocation {
			continue
		}
		if record.Phase != ApplicationCleanupDone {
			return identityFileError(ErrPublisherStateConflict)
		}
		entry := &ApplicationPublication{owner: p, binding: record.Binding, name: applicationPublicationName(record.Binding.ServerURL, invocation)}
		// sync even an uncertain tombstone before unlinking it.
		confirmed, _, err := entry.read(true)
		clear(confirmed.NativeKey)
		if err = errors.Join(context.Cause(ctx), err); err != nil {
			return err
		}
		removeErr := p.files.Remove(entry.name)
		if err := errors.Join(context.Cause(ctx), removeErr); err != nil {
			return errors.Join(ErrApplicationPublicationUncertain, err)
		}
		return nil
	}
	return nil
}

// RequestCleanup fences recovery before the process owner cancels and joins.
func (r *ApplicationPublication) RequestCleanup(ctx context.Context) error {
	return r.updateOwner(ctx, time.Time{})
}

// RenewOwner checkpoints the app's lease without changing its authority fence.
func (r *ApplicationPublication) RenewOwner(ctx context.Context, expires time.Time) error {
	if !expires.After(time.Now()) {
		return identityFileError(ErrPublisherStateConflict)
	}
	return r.updateOwner(ctx, expires)
}

func (r *ApplicationPublication) updateOwner(ctx context.Context, expires time.Time) error {
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if r.owner.closed {
		return identityFileError(ErrPublisherStateConflict)
	}
	record, found, err := r.read(true)
	defer clear(record.NativeKey)
	if err = errors.Join(context.Cause(ctx), err); err != nil {
		return err
	}
	if !found {
		return identityFileError(ErrPublisherStateConflict)
	}
	previous := record
	if expires.IsZero() {
		if record.Phase == ApplicationCleanupPending || record.Phase == ApplicationCleanupDone {
			return nil
		}
		record.Phase, record.ResumePhase = ApplicationCleanupPending, ""
	} else {
		if record.ConfirmationPending() || !record.OwnerExpiresAt.After(time.Now()) || record.Phase == ApplicationDenied || record.Phase == ApplicationCleanupPending || record.Phase == ApplicationCleanupDone {
			return identityFileError(ErrPublisherStateConflict)
		}
		record.OwnerExpiresAt = expires
	}
	record.Revision++
	return r.writeCheckpoint(ctx, previous, record)
}

// FindOwned checks the stable owner and exact target inside the existing record.
// the caller also authenticates the current invocation capability.
func (p *ApplicationPublications) FindOwned(ctx context.Context, invocation, ownerHash, target string) (*ApplicationPublication, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	records, err := p.records()
	if err != nil {
		return nil, err
	}
	var found *ApplicationPublication
	defer func() {
		for _, record := range records {
			clear(record.NativeKey)
		}
	}()
	for _, record := range records {
		if record.Binding.InvocationID != invocation {
			continue
		}
		if found != nil || record.Binding.OwnerHash != ownerHash || record.Binding.Target != target {
			return nil, identityFileError(ErrPublisherStateConflict)
		}
		found = &ApplicationPublication{owner: p, binding: record.Binding, name: applicationPublicationName(record.Binding.ServerURL, invocation)}
	}
	return found, nil
}
