package runtime

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// the held OS lock proves owner lifetime independently of an IPC timeout or
// session expiry. it is released by the kernel even after an ungraceful exit.
func ownerLock(directory string) (*os.File, error) {
	if err := VerifyDirectory(directory); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(directory, "owner.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "connection owner lock")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

// OwnerStopped never signals a PID or treats a temporary read failure as death.
func OwnerStopped(handle string) error {
	f, err := ownerLock(filepath.Dir(handle))
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := os.Lstat(filepath.Join(filepath.Dir(handle), "stopped.json")); err == nil {
		return ReadStopResult(handle)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrCleanup
	}
	return nil
}
