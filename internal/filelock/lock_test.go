package filelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLockContentionAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.lock")
	first, err := Acquire(path, Nonblocking, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	fd := int(first.file.Fd())
	if flags, err := unix.FcntlInt(first.file.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("descriptor flags = %d, %v", flags, err)
	}
	for range 10 {
		if lock, err := Acquire(path, Nonblocking, os.Geteuid()); lock != nil || !errors.Is(err, ErrLocked) {
			t.Fatalf("contending acquisition = %v, %v", lock, err)
		}
	}
	var closed sync.WaitGroup
	for range 4 {
		closed.Go(func() {
			if err := first.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	closed.Wait()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatalf("descriptor remains open: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file removed: %v", err)
	}
	second, err := Acquire(path, Nonblocking, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (*Lock)(nil).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBlockingLockWaitsForRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.lock")
	first, err := Acquire(path, Nonblocking, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	attempting := make(chan struct{})
	joined := false
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
		if !joined {
			select {
			case err := <-acquired:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("blocking acquisition did not finish after cleanup released the lock")
			}
		}
	})
	go func() {
		close(attempting)
		lock, err := Acquire(path, Blocking, os.Geteuid())
		acquired <- errors.Join(err, lock.Close())
	}()
	// This synchronizes the acquisition attempt, not entry into the kernel.
	<-attempting
	select {
	case err := <-acquired:
		joined = true
		t.Fatalf("acquired held lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocking acquisition did not finish")
	}
}

func TestContextLockWaitCanBeCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.lock")
	first, err := Acquire(path, Nonblocking, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		lock, err := AcquireContext(ctx, path, os.Geteuid())
		result <- errors.Join(err, lock.Close())
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("contending acquisition error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("contending acquisition did not honor cancellation")
	}
}

func TestLockRejectsUnsafeFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "test.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(path, Nonblocking, os.Geteuid()+1); lock != nil || err == nil {
		t.Fatal("accepted wrong owner")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(path, Nonblocking, os.Geteuid()); lock != nil || err == nil {
		t.Fatal("accepted wrong mode")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink.lock")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{symlink, root} {
		if lock, err := Acquire(path, Nonblocking, os.Geteuid()); lock != nil || err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	lock, err := Acquire(path, Nonblocking, os.Geteuid())
	if err != nil {
		t.Fatalf("rejected acquisition left file locked: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
