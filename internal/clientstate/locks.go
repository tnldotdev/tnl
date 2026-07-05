package clientstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/filelock"
)

var ErrLocked = errors.New("clientstate: state is locked by another process")

// Lock owns a local state lock. Store methods choose its scope and path.
type Lock = filelock.Lock

func (s *Store) LockHostname(hostname string) (*Lock, error) {
	if strings.TrimSpace(hostname) == "" {
		return nil, errors.New("clientstate: hostname is required")
	}
	digest := sha256.Sum256([]byte(hostname))
	return openLock(filepath.Join(s.locksDir, hex.EncodeToString(digest[:])+".lock"), "hostname")
}

func (s *Store) LockControlSession() (*Lock, error) {
	return openLock(filepath.Join(s.locksDir, "control-session.lock"), "control session")
}

func LockControlSessionContext(ctx context.Context, store *Store) (*Lock, error) {
	if store == nil {
		return nil, errors.New("clientstate: state store is required")
	}
	return retryLock(ctx, store.LockControlSession)
}

func retryLock(ctx context.Context, acquire func() (*Lock, error)) (*Lock, error) {
	for {
		lock, err := acquire()
		if !errors.Is(err, ErrLocked) {
			return lock, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func prepareRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("clientstate: state directory is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("clientstate: resolve state directory: %w", err)
	}
	if info, statErr := os.Lstat(root); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("clientstate: state directory must not be a symlink")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("clientstate: inspect state directory: %w", statErr)
	}
	root, err = canonicalPath(root)
	if err != nil {
		return "", err
	}
	if err := validateTrustedAncestors(filepath.Dir(root)); err != nil {
		return "", err
	}
	if err := ensurePrivateDir(root); err != nil {
		return "", err
	}
	return root, nil
}

func canonicalPath(path string) (string, error) {
	cursor := filepath.Clean(path)
	var missing []string
	for {
		if _, err := os.Lstat(cursor); err == nil {
			resolved, err := filepath.EvalSymlinks(cursor)
			if err != nil {
				return "", fmt.Errorf("clientstate: resolve state directory: %w", err)
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("clientstate: inspect state directory: %w", err)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", errors.New("clientstate: no existing state directory ancestor")
		}
		missing = append(missing, filepath.Base(cursor))
		cursor = parent
	}
}

func validateTrustedAncestors(path string) error {
	cursor := filepath.Clean(path)
	for {
		info, err := os.Lstat(cursor)
		if errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(cursor)
			if parent == cursor {
				return errors.New("clientstate: no existing state directory ancestor")
			}
			cursor = parent
			continue
		}
		if err != nil {
			return fmt.Errorf("clientstate: inspect state directory ancestor: %w", err)
		}
		writable := info.Mode().Perm()&0o022 != 0
		sticky := info.Mode()&os.ModeSticky != 0
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || writable && !sticky {
			return errors.New("clientstate: state directory has an untrusted writable ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return errors.New("clientstate: state directory has an untrusted owner")
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return nil
		}
		cursor = parent
	}
}

func openLock(path, kind string) (*Lock, error) {
	return openLockOperation(path, kind, filelock.Nonblocking)
}

func openBlockingLock(path, kind string) (*Lock, error) {
	return openLockOperation(path, kind, filelock.Blocking)
}

func openLockOperation(path, kind string, mode filelock.Mode) (*Lock, error) {
	lock, err := filelock.Acquire(path, mode, os.Geteuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, fmt.Errorf("clientstate: lock %s state: %w", kind, err)
	}
	return lock, nil
}

func ensurePrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if err := validatePrivateFile(info, true); err != nil {
			return fmt.Errorf("clientstate: state directory: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clientstate: inspect state directory: %w", err)
	} else if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("clientstate: create state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("clientstate: inspect state directory: %w", err)
	}
	return validatePrivateFile(info, true)
}

func privateSubdir(parent, name string) (string, error) {
	path := filepath.Join(parent, name)
	if info, err := os.Lstat(path); err == nil {
		if err := validatePrivateFile(info, true); err != nil {
			return "", fmt.Errorf("clientstate: state path: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("clientstate: inspect state path: %w", err)
	} else if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("clientstate: create state path: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("clientstate: inspect state path: %w", err)
	}
	if err := validatePrivateFile(info, true); err != nil {
		return "", fmt.Errorf("clientstate: state path: %w", err)
	}
	return path, nil
}

func validatePrivateFile(info os.FileInfo, directory bool) error {
	wantMode := os.FileMode(0o600)
	if directory {
		wantMode = 0o700
	}
	if info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("not a real private file")
	}
	if info.Mode().Perm() != wantMode {
		return fmt.Errorf("permissions are %04o, want %04o", info.Mode().Perm(), wantMode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("not owned by the current user")
	}
	return nil
}

func LockHostnameContext(ctx context.Context, store *Store, hostname string) (*Lock, error) {
	for {
		lock, err := store.LockHostname(hostname)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, ErrLocked) {
			return nil, err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
