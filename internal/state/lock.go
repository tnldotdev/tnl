package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrLocked reports that another process owns the state directory.
var ErrLocked = errors.New("state: directory is locked by another process")

// DirectoryLock owns the exclusive process lock for a daemon state directory.
type DirectoryLock struct {
	file *os.File
	once sync.Once
}

// LockDirectory exclusively locks a prepared daemon state directory.
func LockDirectory(dir string) (*DirectoryLock, error) {
	dir, err := prepareDirectory(dir)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, ".tnld.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: open directory lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("state: secure directory lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("state: lock directory: %w", err)
	}
	return &DirectoryLock{file: file}, nil
}

// RequireDirectoryOwner rejects state not owned by the effective user.
func RequireDirectoryOwner(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("state: stat directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("state: directory is not owned by the current user")
	}
	if !info.IsDir() {
		return errors.New("state: path is not a directory")
	}
	return nil
}

// LockExistingDirectory exclusively locks an existing daemon state lock.
func LockExistingDirectory(dir string) (*DirectoryLock, error) {
	if err := RequireDirectoryOwner(dir); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, ".tnld.lock"), os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("state: open existing directory lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("state: lock directory: %w", err)
	}
	return &DirectoryLock{file: file}, nil
}

// Close releases the directory lock.
func (l *DirectoryLock) Close() error {
	if l == nil {
		return nil
	}
	var result error
	l.once.Do(func() {
		result = errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close())
	})
	return result
}
