package publisherjob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"syscall"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

type fileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// the encrypted manifest detects same-content file replacement across boots,
// when there is no live descriptor left to compare against the new path.
func (r *Registry) verifyManifest(ctx context.Context) error {
	want := map[string]fileIdentity{}
	for path, info := range r.pins {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUnsafeState
		}
		want[path] = fileIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}
	}
	value, found, err := r.database.PublisherJobFileManifest(ctx)
	if err != nil {
		return err
	}
	if found {
		var saved map[string]fileIdentity
		if json.Unmarshal(value, &saved) != nil || !maps.Equal(saved, want) {
			return ErrUnsafeState
		}
		return nil
	}
	value, err = json.Marshal(want)
	if err != nil {
		return err
	}
	return r.database.SavePublisherJobFileManifest(ctx, value)
}

func privateInfo(info os.FileInfo, owner int, directory bool) bool {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(owner) && info.Mode().Perm() == mode && info.Mode()&os.ModeSymlink == 0 && info.IsDir() == directory && (directory || info.Mode().IsRegular())
}

func (r *Registry) pin() error {
	for _, path := range []string{r.root, filepath.Join(r.root, "locks"), clientstate.DatabasePath(r.root), clientstate.WrappingKeyPath(r.root), filepath.Join(r.root, "jobs.lock")} {
		info, err := os.Lstat(path)
		if err != nil || !privateInfo(info, r.owner, path == r.root || path == filepath.Join(r.root, "locks")) {
			return ErrUnsafeState
		}
		r.pins[path] = info
	}
	key, err := r.keyDigest()
	if err != nil {
		return err
	}
	r.key = key
	return r.validate()
}

func (r *Registry) keyDigest() ([]byte, error) {
	f, err := clientstate.OpenPrivateFile(clientstate.WrappingKeyPath(r.root))
	if err != nil {
		return nil, ErrUnsafeState
	}
	defer f.Close()
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, ErrUnsafeState
	}
	digest := sha256.Sum256(key)
	return digest[:], nil
}

func (r *Registry) validate() error {
	canonical, err := filepath.EvalSymlinks(r.root)
	if err != nil || canonical != r.root {
		return ErrUnsafeState
	}
	if err := trustedAncestors(filepath.Dir(r.root), r.owner); err != nil {
		return err
	}
	for path, pinned := range r.pins {
		current, err := os.Lstat(path)
		if err != nil || !privateInfo(current, r.owner, pinned.IsDir()) || !os.SameFile(pinned, current) {
			return ErrUnsafeState
		}
	}
	key, err := r.keyDigest()
	if err != nil || !bytes.Equal(key, r.key) {
		return ErrUnsafeState
	}
	// SQLite sidecars may appear and disappear; they must remain private.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := os.Lstat(clientstate.DatabasePath(r.root) + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !privateInfo(info, r.owner, false) {
			return ErrUnsafeState
		}
	}
	return nil
}

func trustedAncestors(path string, owner int) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return ErrUnsafeState
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 && stat.Uid != uint32(owner) || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return ErrUnsafeState
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func trustedStatePath(path string, owner int) error {
	for {
		_, err := os.Lstat(path)
		if err == nil {
			return trustedAncestors(path, owner)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ErrUnsafeState
		}
		parent := filepath.Dir(path)
		if parent == path {
			return ErrUnsafeState
		}
		path = parent
	}
}
