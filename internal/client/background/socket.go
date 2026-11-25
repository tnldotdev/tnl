package background

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
)

func selectStateRoot(root string, create bool) (string, error) {
	if root == "" {
		var err error
		root, err = clientstate.DefaultDir()
		if err != nil {
			return "", err
		}
	}
	if create {
		root, err := clientstate.PrepareRoot(root)
		return root, failure.Wrap("prepare background job state", failure.ClientStateUnavailable, err)
	}
	// a missing root is empty; management does not create/open client state.
	if err := privateDirectory(root, false); err != nil {
		return "", err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(root)
}

// use one short unix path, even if the canonical root exceeds the socket
// limit. the private socket tree is the registry; no job metadata is persisted
// separately. only the selected canonical state root determines its scope.
func scopeDirectory(root string, create bool) (string, error) {
	base := fmt.Sprintf("/tmp/tnl-j-%d", os.Geteuid())
	if err := privateDirectory(base, create); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(root))
	dir := filepath.Join(base, fmt.Sprintf("%x", sum[:16]))
	return dir, privateDirectory(dir, create)
}

func privateDirectory(path string, create bool) error {
	if create {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return failure.Wrap("inspect background job directory", failure.ClientStateUnavailable, clientstate.ValidatePrivateFile(info, true))
}

func jobPaths(scope, id string) (dir, socket string) {
	dir = filepath.Join(scope, id)
	return dir, filepath.Join(dir, "s")
}

func privateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return failure.Wrap("inspect background job socket", failure.ClientStateUnavailable, errors.New("unsafe background job socket"))
	}
	return nil
}

type socketReservation struct {
	dir, path string
	info      os.FileInfo
}

func reserveSocket(scope, id string) (socketReservation, *net.UnixListener, error) {
	dir, path := jobPaths(scope, id)
	// an ID is allocated once. never reuse a directory or unlink an existing
	// socket, including one left behind by a killed process.
	if err := os.Mkdir(dir, 0o700); err != nil {
		return socketReservation{}, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return socketReservation{}, nil, err
	}
	reservation := socketReservation{dir: dir, path: path, info: info}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return socketReservation{}, nil, errors.Join(err, reservation.remove())
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		return socketReservation{}, nil, errors.Join(err, listener.Close(), reservation.remove())
	}
	return reservation, listener, nil
}

func (s socketReservation) remove() error {
	current, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(s.info, current) {
		return errors.New("background job socket directory changed")
	}
	err = os.Remove(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err = os.Remove(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
