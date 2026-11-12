package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func applicationStateOwner(t *testing.T, configured int) *ApplicationPublications {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenApplicationPublications(root, root, root, configured)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func applicationStateBinding(t *testing.T) ApplicationPublicationBinding {
	t.Helper()
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("stable owner secret"))
	return ApplicationPublicationBinding{ServerURL: "https://control.example", InvocationID: id, OwnerHash: hex.EncodeToString(digest[:]), PID: os.Getpid(), Target: "http://127.0.0.1:3000", ConfigurationDigest: strings.Repeat("1", 64), RequestDigest: strings.Repeat("2", 64), Namespace: "apps.example", SourceKind: "oidc", SourceMachineID: "mci_0123456789ABCDEFGHIJKL"}
}

func TestApplicationPublicationPendingKeySurvivesUncertainWriteAndReopen(t *testing.T) {
	for _, kind := range []string{"oidc", "registered_key"} {
		t.Run(kind, func(t *testing.T) {
			p := applicationStateOwner(t, 0)
			binding := applicationStateBinding(t)
			if kind == "registered_key" {
				binding.SourceKind, binding.SourceKeyID = kind, "registered-source"
			}
			p.files.syncFile = func(file *os.File) error {
				info, err := file.Stat()
				if err == nil && info.IsDir() {
					return syscall.EIO
				}
				if err != nil {
					return err
				}
				return file.Sync()
			}
			if _, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute)); !errors.Is(err, syscall.EIO) {
				t.Fatal("uncertain pending checkpoint was treated as durable", err)
			}
			data, found, err := p.files.Read(applicationPublicationName(binding.ServerURL, binding.InvocationID), maxApplicationPublicationBytes)
			if err != nil || !found {
				t.Fatal("uncertain write did not leave a recoverable checkpoint", err)
			}
			var uncertain ApplicationPublicationRecord
			if err := json.Unmarshal(data, &uncertain); err != nil {
				t.Fatal(err)
			}
			clear(data)
			p.files.syncFile = nil
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenApplicationPublications(p.stateRoot, p.projectRoot, p.worktreeRoot, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			entry, err := reopened.Publication(t.Context(), binding, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			record, err := entry.Snapshot(t.Context())
			if err != nil || !bytes.Equal(record.NativeKey, uncertain.NativeKey) || record.Nonce != uncertain.Nonce || !workloadproof.ValidNonce(record.Nonce) || record.Phase != ApplicationExchangePending {
				t.Fatal("recovery changed the original key/nonce/intent", err)
			}
		})
	}
}

func TestApplicationPublicationScopeAndLiveOwnerCannotBeRebound(t *testing.T) {
	p := applicationStateOwner(t, 0)
	binding := applicationStateBinding(t)
	if _, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenApplicationPublications(p.stateRoot, p.projectRoot, p.worktreeRoot, 0); !errors.Is(err, ErrLocked) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("another native process could acquire this owner", err)
	}
	for name, change := range map[string]func(*ApplicationPublicationBinding){
		"owner":    func(b *ApplicationPublicationBinding) { b.OwnerHash = strings.Repeat("3", 64) },
		"pid":      func(b *ApplicationPublicationBinding) { b.PID++ },
		"target":   func(b *ApplicationPublicationBinding) { b.Target = "http://127.0.0.1:4000" },
		"snapshot": func(b *ApplicationPublicationBinding) { b.ConfigurationDigest = strings.Repeat("4", 64) },
		"request":  func(b *ApplicationPublicationBinding) { b.RequestDigest = strings.Repeat("5", 64) },
		"server":   func(b *ApplicationPublicationBinding) { b.ServerURL = "https://other.example" },
		"scope":    func(b *ApplicationPublicationBinding) { b.Namespace = "other.example" },
		"source":   func(b *ApplicationPublicationBinding) { b.SourceKind = "installed" },
		"machine":  func(b *ApplicationPublicationBinding) { b.SourceMachineID = "mci_1123456789ABCDEFGHIJKL" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			if _, err := p.Publication(t.Context(), changed, time.Now().Add(time.Minute)); err == nil {
				t.Fatal("changed request/owner created or claimed another key")
			}
		})
	}
}

func TestApplicationPublicationRejectsPrivateFileAndCorruptRecord(t *testing.T) {
	for _, corruption := range []string{"permissions", "symlink", "scope", "unknown", "duplicate"} {
		t.Run(corruption, func(t *testing.T) {
			p := applicationStateOwner(t, 0)
			binding := applicationStateBinding(t)
			entry, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(p.files.Path(), entry.name)
			switch corruption {
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				outside := filepath.Join(t.TempDir(), "record")
				if err := os.Rename(path, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			default:
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if corruption == "scope" {
					data = bytes.Replace(data, []byte(`"project_root":"`+p.projectRoot+`"`), []byte(`"project_root":"/wrong"`), 1)
				}
				if corruption == "unknown" {
					data = append([]byte(`{"assertion":"must-not-persist",`), data[1:]...)
				}
				if corruption == "duplicate" {
					data = append([]byte(`{"version":1,`), data[1:]...)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := entry.Snapshot(t.Context()); err == nil {
				t.Fatal("untrusted private record accepted")
			}
		})
	}
}

func TestApplicationPublicationCleanupRemainsPossibleAtCapacityAndRemovalRetries(t *testing.T) {
	p := applicationStateOwner(t, ApplicationPublicationCapacity-1)
	binding := applicationStateBinding(t)
	entry, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	record, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = ApplicationCleanupPending
	if err := entry.Checkpoint(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publication(t.Context(), applicationStateBinding(t), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("failed cleanup was evicted at capacity")
	}
	if pending, err := p.Pending(t.Context()); err != nil || len(pending) != 1 {
		t.Fatal("cleanup became unavailable at creation capacity", err)
	}
	record, err = entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	record.Phase, record.NativeKey = ApplicationCleanupDone, nil
	if err := entry.Checkpoint(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	p.files.syncFile = func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			if _, err := os.Lstat(filepath.Join(p.files.Path(), entry.name)); errors.Is(err, os.ErrNotExist) {
				return syscall.EIO
			}
		}
		return file.Sync()
	}
	if err := entry.RemoveCompleted(t.Context()); !errors.Is(err, syscall.EIO) {
		t.Fatal("uncertain removal was quietly successful", err)
	}
	if _, err := os.Lstat(filepath.Join(p.files.Path(), entry.name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removal fault did not cross the unlink boundary", err)
	}
	p.files.syncFile = nil
	if err := entry.RemoveCompleted(t.Context()); err != nil {
		t.Fatal("uncertain removal could not resync its directory", err)
	}
}

func TestApplicationPublicationStaleCheckpointAndCanceledFailurePreserveState(t *testing.T) {
	p := applicationStateOwner(t, 0)
	entry, err := p.Publication(t.Context(), applicationStateBinding(t), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	first, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	first.Phase = ApplicationCleanupPending
	if err := entry.Checkpoint(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := entry.Checkpoint(t.Context(), first); err == nil {
		t.Fatal("stale result overwrote a newer checkpoint")
	}
	current, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("app stopped")
	cancel(cause)
	current.Phase, current.NativeKey = ApplicationCleanupDone, nil
	if err := entry.Checkpoint(ctx, current); !errors.Is(err, cause) {
		t.Fatal("canceled checkpoint lost its cause", err)
	}
	unchanged, err := entry.Snapshot(t.Context())
	if err != nil || unchanged.Phase != ApplicationCleanupPending || len(unchanged.NativeKey) == 0 {
		t.Fatal("canceled cleanup discarded the original key obligation", err)
	}
}

func TestApplicationPublicationCompletedChurnRetiresOnlySyncedTombstones(t *testing.T) {
	p := applicationStateOwner(t, ApplicationPublicationCapacity-1)
	for range ApplicationPublicationCapacity + 16 {
		binding := applicationStateBinding(t)
		entry, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal("completed invocations exhausted active capacity", err)
		}
		if err := p.ForgetCompleted(t.Context(), binding.InvocationID); err == nil {
			t.Fatal("pending obligation was evicted")
		}
		if err := entry.RequestCleanup(t.Context()); err != nil {
			t.Fatal(err)
		}
		record, err := entry.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		clear(record.NativeKey)
		record.Phase, record.NativeKey = ApplicationCleanupDone, nil
		if err := entry.Checkpoint(t.Context(), record); err != nil {
			t.Fatal(err)
		}
		if err := p.ForgetCompleted(t.Context(), binding.InvocationID); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := p.files.open()
	if err != nil {
		t.Fatal(err)
	}
	defer entries.Close()
	dir, err := entries.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	files, err := dir.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "owner.lock" {
		t.Fatal("completed keys/tombstones accumulated")
	}
}

func TestApplicationPublicationOrphanTemporaryIsNotRecoveryAuthority(t *testing.T) {
	p := applicationStateOwner(t, 0)
	name := ".identity-" + strings.Repeat("a", 32)
	if err := os.WriteFile(filepath.Join(p.files.Path(), name), []byte("orphaned private checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(p.files.Path(), name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphaned secret-bearing temporary was retained", err)
	}
}

func TestApplicationPublicationCompletedTailCannotMakeCleanupUnscannable(t *testing.T) {
	p := applicationStateOwner(t, 0)
	// seed a completed tail directly through its validated private writer, rather
	// than rescanning an ever-growing directory for every fixture tombstone.
	record := ApplicationPublicationRecord{Version: 1, Revision: 1, StateRoot: p.stateRoot, ProjectRoot: p.projectRoot, WorktreeRoot: p.worktreeRoot, Phase: ApplicationCleanupDone, Nonce: strings.Repeat("a", 32), OwnerExpiresAt: time.Now().Add(time.Minute)}
	for range 2*ApplicationPublicationCapacity - 1 {
		binding := applicationStateBinding(t)
		entry := &ApplicationPublication{owner: p, binding: binding, name: applicationPublicationName(binding.ServerURL, binding.InvocationID)}
		record.Binding = binding
		if err := entry.write(record); err != nil {
			t.Fatal(err)
		}
	}
	binding := applicationStateBinding(t)
	pending, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publication(t.Context(), applicationStateBinding(t), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("creation exceeded the bounded completed tail")
	}
	entries, err := p.Pending(t.Context())
	if err != nil || len(entries) != 1 || entries[0].Binding() != binding {
		t.Fatal("completed tail made the pending cleanup inaccessible", err)
	}
	if err := pending.RequestCleanup(t.Context()); err != nil {
		t.Fatal("cleanup became unavailable at the total record bound", err)
	}
}

func TestApplicationPublicationOwnerLockReplacementFencesExistingOwner(t *testing.T) {
	p := applicationStateOwner(t, 0)
	entry, err := p.Publication(t.Context(), applicationStateBinding(t), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.files.Path(), "owner.lock")
	if err := os.Rename(path, path+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Snapshot(t.Context()); err == nil {
		t.Fatal("replaced process lock left old owner authoritative")
	}
	if _, err := p.Pending(t.Context()); err == nil {
		t.Fatal("scan accepted a replaced process lock")
	}
}

func TestApplicationPublicationUncertainAcceptedSessionMustResync(t *testing.T) {
	p := applicationStateOwner(t, 0)
	entry, err := p.Publication(t.Context(), applicationStateBinding(t), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	record, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record.NativeKey)
	record.Phase, record.SessionID = ApplicationSessionAccepted, "mps_0123456789ABCDEFGHIJKL"
	record.Publisher = &authorityv1.PublisherEnrollmentResult{ClientId: "pub_0123456789ABCDEFGHIJKL", KeyId: "pkey_0123456789ABCDEFGHIJKL", GrantId: "pgrant_0123456789ABCDEFGHIJKL", TeamId: "tm_0123456789ABCDEFGHIJKL", Kind: authorityv1.Namespace, Namespace: new(record.Binding.Namespace), DomainId: new("dom_0123456789ABCDEFGHIJKL")}
	record.AccessExpiresAt, record.IdentityExpiresAt, record.RenewAfter = time.Now().Add(time.Minute), time.Now().Add(5*time.Minute), time.Now().Add(30*time.Second)
	directories := 0
	p.files.syncFile = func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			directories++
			if directories >= 2 {
				return syscall.EIO
			}
		}
		return file.Sync()
	}
	if err := entry.Checkpoint(t.Context(), record); !errors.Is(err, syscall.EIO) {
		t.Fatal("uncertain session was acknowledged", err)
	}
	if _, err := entry.Snapshot(t.Context()); !errors.Is(err, syscall.EIO) {
		t.Fatal("uncertain session became usable before resync", err)
	}
	p.files.syncFile = nil
	accepted, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(accepted.NativeKey)
	if accepted.Phase != ApplicationSessionAccepted || accepted.SessionID != record.SessionID || !bytes.Equal(accepted.NativeKey, record.NativeKey) || accepted.Nonce != record.Nonce {
		t.Fatal("resync replaced uncertain accepted authority")
	}
}
