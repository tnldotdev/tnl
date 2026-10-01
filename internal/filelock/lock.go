// Package filelock acquires user-owned, mode-0600 regular lock files on Unix.
// It protects the final path component with O_NOFOLLOW, not directory ancestry.
// callers own trusted directories, path derivation, and lock lifetime.
package filelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Mode controls whether acquisition waits for a competing holder.
type Mode bool

const (
	Nonblocking Mode = false
	Blocking    Mode = true
)

// ErrLocked reports contention in Nonblocking mode.
var ErrLocked = errors.New("filelock: already locked")

const retryInterval = 100 * time.Millisecond

// Lock owns a locked descriptor. do not copy it; Close releases it exactly once.
type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// Acquire opens or creates path and takes an exclusive lock. blocking acquisition
// has no cancellation; use AcquireContext for a cancelable wait.
// ownerUID is explicit because callers may require the real or effective UID.
func Acquire(path string, mode Mode, ownerUID int) (*Lock, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelock: open: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	locked := false
	defer func() {
		if !locked {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("filelock: inspect: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || ownerUID < 0 || stat.Uid != uint32(ownerUID) {
		return nil, errors.New("filelock: lock must be a user-owned regular file with mode 0600")
	}
	operation := unix.LOCK_EX
	if mode == Nonblocking {
		operation |= unix.LOCK_NB
	}
	if err := unix.Flock(descriptor, operation); err != nil {
		if mode == Nonblocking && errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("filelock: acquire: %w", err)
	}
	locked = true
	return &Lock{file: file}, nil
}

// AcquireContext retries nonblocking acquisition until it succeeds or ctx is
// canceled. it avoids an uncancelable wait in the kernel.
func AcquireContext(ctx context.Context, path string, ownerUID int) (*Lock, error) {
	for {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		lock, err := Acquire(path, Nonblocking, ownerUID)
		if !errors.Is(err, ErrLocked) {
			return lock, err
		}
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

// Close unlocks and closes the descriptor, without removing the lock file. it is
// nil-safe and may be called concurrently; repeated calls return the same error.
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() { l.err = errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close()) })
	return l.err
}
