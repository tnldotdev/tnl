package state

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func applicationAcceptedRecord(t *testing.T, entry *ApplicationPublication, expiry time.Time) ApplicationPublicationRecord {
	t.Helper()
	record, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	record.Phase, record.SessionID = ApplicationSessionAccepted, "mps_0123456789ABCDEFGHIJKL"
	record.Publisher = &authorityv1.PublisherEnrollmentResult{ClientId: "pub_0123456789ABCDEFGHIJKL", KeyId: "pkey_0123456789ABCDEFGHIJKL", GrantId: "pgrant_0123456789ABCDEFGHIJKL", TeamId: "tm_0123456789ABCDEFGHIJKL", Kind: authorityv1.Namespace, Namespace: new(record.Binding.Namespace), DomainId: new("dom_0123456789ABCDEFGHIJKL")}
	record.IdentityExpiresAt, record.AccessExpiresAt, record.RenewAfter = expiry, expiry, expiry.Add(-time.Second)
	return record
}

func TestApplicationPublicationCancellationDuringReadAndWriteNeverAcknowledgesSuccess(t *testing.T) {
	for _, operation := range []string{"snapshot-read", "checkpoint-read", "checkpoint-file-sync", "checkpoint-directory-sync"} {
		for _, independent := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/cancellation", true: "/independent-failure"}[independent], func(t *testing.T) {
				p := applicationStateOwner(t, 0)
				entry, err := p.Publication(t.Context(), applicationStateBinding(t), time.Now().Add(time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				original, err := entry.Snapshot(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer clear(original.NativeKey)
				next := applicationAcceptedRecord(t, entry, time.Now().Add(time.Minute))
				defer clear(next.NativeKey)
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				cause := errors.New("original application operation stopped")
				directories := 0
				fired := false
				p.files.syncFile = func(file *os.File) error {
					info, err := file.Stat()
					if err != nil {
						return err
					}
					if info.IsDir() {
						directories++
					}
					trigger := operation == "snapshot-read" || operation == "checkpoint-read" || operation == "checkpoint-file-sync" && strings.Contains(file.Name(), ".identity-") || operation == "checkpoint-directory-sync" && info.IsDir() && directories == 2
					if trigger && !fired {
						fired = true
						cancel(cause)
						if independent {
							return syscall.EIO
						}
					}
					return file.Sync()
				}
				if operation == "snapshot-read" {
					record, readErr := entry.Snapshot(ctx)
					err = readErr
					if len(record.NativeKey) != 0 {
						t.Fatal("canceled read exposed usable key facts")
					}
				} else {
					err = entry.Checkpoint(ctx, next)
				}
				if !fired || !errors.Is(err, cause) || independent && !errors.Is(err, syscall.EIO) {
					t.Fatal("synchronous storage cancellation was acknowledged or lost a cause", err)
				}
				p.files.syncFile = nil
				stored, err := entry.Snapshot(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer clear(stored.NativeKey)
				if stored.Nonce != original.Nonce || !bytes.Equal(stored.NativeKey, original.NativeKey) {
					t.Fatal("canceled storage replaced original native tuple")
				}
				if stored.Publisher != nil && !stored.ConfirmationPending() {
					t.Fatal("late write became confirmed authority")
				}
			})
		}
	}
}

func TestApplicationPublicationLateAuthoritySyncRetainsOriginalConfirmationDeadlineOnReopen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := applicationStateOwner(t, 0)
		binding := applicationStateBinding(t)
		entry, err := p.Publication(t.Context(), binding, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		accepted := applicationAcceptedRecord(t, entry, deadline)
		defer clear(accepted.NativeKey)
		if err := entry.Checkpoint(t.Context(), accepted); err != nil {
			t.Fatal(err)
		}
		record, err := entry.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(record.NativeKey)
		record.Phase, record.ResumePhase = ApplicationRefreshPending, record.Phase
		if err := entry.Checkpoint(t.Context(), record); err != nil {
			t.Fatal(err)
		}
		record, err = entry.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(record.NativeKey)
		record.Phase, record.ResumePhase = ApplicationSessionAccepted, ""
		record.IdentityExpiresAt, record.AccessExpiresAt, record.RenewAfter = deadline.Add(time.Minute), deadline.Add(time.Minute), deadline.Add(30*time.Second)
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()
		blocked := false
		p.files.syncFile = func(file *os.File) error {
			if !blocked && strings.Contains(file.Name(), ".identity-") {
				blocked = true
				<-ctx.Done()
			}
			return file.Sync()
		}
		if err := entry.Checkpoint(ctx, record); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrApplicationPublicationUncertain) {
			t.Fatal("late authority sync returned success", err)
		}
		p.files.syncFile = nil
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenApplicationPublications(p.stateRoot, p.projectRoot, p.worktreeRoot, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		entry, err = reopened.Publication(t.Context(), binding, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		pending, err := entry.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(pending.NativeKey)
		if !pending.ConfirmationPending() || !pending.ConfirmationDeadline.Equal(deadline) || !bytes.Equal(pending.NativeKey, record.NativeKey) || pending.Nonce != record.Nonce {
			t.Fatal("late candidate lost original confirmation fence or tuple")
		}
		if err := entry.Checkpoint(t.Context(), pending); !errors.Is(err, ErrApplicationConfirmationExpired) {
			t.Fatal("reopen confirmed an expired original deadline", err)
		}
		if err := entry.RenewOwner(t.Context(), time.Now().Add(time.Minute)); err == nil {
			t.Fatal("owner renewal bypassed unconfirmed authority")
		}
		if err := entry.RequestCleanup(t.Context()); err != nil {
			t.Fatal("late candidate could not retain original-key cleanup", err)
		}
	})
}
