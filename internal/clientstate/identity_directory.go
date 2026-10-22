package clientstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tnldotdev/tnl/internal/failure"
)

// PrivateDirectory holds small durable identity files. SQLite and its wrapping
// key remain in the runtime state directory, independently of this filesystem.
type PrivateDirectory struct {
	path     string
	pin      os.FileInfo
	syncFile func(*os.File) error
}

func OpenPrivateDirectory(path string) (*PrivateDirectory, error) {
	root, err := prepareRoot(path)
	if err != nil {
		return nil, identityFileError(err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, identityFileError(err)
	}
	return &PrivateDirectory{path: root, pin: info}, nil
}

func (d *PrivateDirectory) Path() string { return d.path }

func (d *PrivateDirectory) validate() error {
	info, err := os.Lstat(d.path)
	if err == nil {
		err = validatePrivateFile(info, true)
	}
	if err == nil && !os.SameFile(d.pin, info) {
		err = ErrPublisherStateConflict
	}
	return identityFileError(err)
}

func (d *PrivateDirectory) open() (*os.Root, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(d.path)
	if err != nil {
		return nil, identityFileError(err)
	}
	info, err := root.Stat(".")
	if err == nil && !os.SameFile(d.pin, info) {
		err = ErrPublisherStateConflict
	}
	if err != nil {
		_ = root.Close()
		return nil, identityFileError(err)
	}
	return root, nil
}

func (d *PrivateDirectory) sync(file *os.File) error {
	if d.syncFile != nil {
		return d.syncFile(file)
	}
	return file.Sync()
}

func (d *PrivateDirectory) syncDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.sync(directory), directory.Close())
}

func (d *PrivateDirectory) Scoped(scope string) (*PrivateDirectory, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(scope))
	return OpenPrivateDirectory(filepath.Join(d.path, hex.EncodeToString(digest[:])))
}

func privateFilename(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, "\\\x00\r\n")
}

func (d *PrivateDirectory) Read(name string, limit int64) ([]byte, bool, error) {
	if !privateFilename(name) || limit <= 0 {
		return nil, false, identityFileError(ErrPublisherStateConflict)
	}
	root, err := d.open()
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err == nil {
		err = validatePrivateFile(info, false)
	}
	if err != nil {
		return nil, false, identityFileError(err)
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, identityFileError(err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err == nil {
		err = validatePrivateFile(opened, false)
	}
	// a concurrent atomic replacement may change the inode between Lstat and
	// OpenFile. the pinned directory and no-follow opened file remain authoritative.
	if err != nil {
		return nil, false, identityFileError(err)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = ErrPublisherStateConflict
	}
	if err == nil {
		err = d.validate()
	}
	if err != nil {
		clear(data)
		return nil, false, identityFileError(err)
	}
	return data, true, nil
}

// Write atomically replaces a complete file after syncing its private temporary
// file. callers serialize read/modify/write with Lock on the same filesystem.
func (d *PrivateDirectory) Write(name string, data []byte) error {
	if !privateFilename(name) || len(data) == 0 {
		return identityFileError(ErrPublisherStateConflict)
	}
	root, err := d.open()
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat(name); err == nil {
		if err = validatePrivateFile(info, false); err != nil {
			return identityFileError(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return identityFileError(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return identityFileError(err)
	}
	temporary := ".identity-" + hex.EncodeToString(nonce[:])
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return identityFileError(err)
	}
	defer root.Remove(temporary)
	defer file.Close()
	if _, err = file.Write(data); err == nil {
		err = d.sync(file)
	}
	if err == nil {
		err = file.Close()
	}
	if err == nil {
		err = d.validate()
	}
	if err == nil {
		err = root.Rename(temporary, name)
	}
	if err == nil {
		err = d.syncDirectory(root)
	}
	return identityFileError(err)
}

// Sync recovers an uncertain rename/sync outcome before a recovered key or
// staged certificate may authorize another external issuance/install operation.
func (d *PrivateDirectory) Sync(name string) error {
	if !privateFilename(name) {
		return identityFileError(ErrPublisherStateConflict)
	}
	root, err := d.open()
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return identityFileError(err)
	}
	info, err := file.Stat()
	if err == nil {
		err = validatePrivateFile(info, false)
	}
	if err == nil {
		err = d.sync(file)
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = d.syncDirectory(root)
	}
	return identityFileError(err)
}

func (d *PrivateDirectory) Lock(ctx context.Context, name string) (*Lock, error) {
	if !privateFilename(name) {
		return nil, identityFileError(ErrPublisherStateConflict)
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	lock, err := openLockContext(ctx, filepath.Join(d.path, name), "publisher identity files")
	if err == nil {
		err = d.validate()
	}
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		return nil, identityFileError(err)
	}
	return lock, nil
}

func identityFileError(err error) error {
	if err == nil {
		return nil
	}
	if _, typed := failure.Of(err); typed {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	reason := failure.PublisherIdentityStateInvalid
	for _, temporary := range []error{syscall.EIO, syscall.ENOSPC, syscall.ESTALE, syscall.ETIMEDOUT, syscall.EAGAIN} {
		if errors.Is(err, temporary) {
			reason = failure.PublisherIdentityStateUnavailable
			break
		}
	}
	return failure.Wrap("use durable publisher identity files", reason, err)
}

// WithIdentityDirectory selects the same filesystem owner used by local
// publishers. deployed tasks override this path with a persistent mount.
func (s *Store) WithIdentityDirectory(path string) (*Store, error) {
	files, err := OpenPrivateDirectory(path)
	if err != nil {
		return nil, err
	}
	copy := *s
	copy.identityDir = files.Path()
	return &copy, nil
}

func (s *Store) IdentityDirectory() string { return s.identityDir }

func (s *Store) PublisherIdentityFiles(team, publisher string) (*PrivateDirectory, error) {
	root, err := OpenPrivateDirectory(s.identityDir)
	if err != nil {
		return nil, err
	}
	scope, _ := json.Marshal([]string{s.controlEndpoint, team, publisher})
	return root.Scoped(string(scope))
}
