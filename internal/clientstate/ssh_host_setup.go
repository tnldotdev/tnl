package clientstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const maxSSHHostSetupState = 64 << 10

// SSHHostSetupState holds one server/team/hostname lock across read, external
// operations, and checkpoint writes. documents use the normal state protector;
// they are not publisher-job records and never enter browser-safe snapshots.
type SSHHostSetupState struct {
	store       *Store
	root        *os.Root
	lock        *Lock
	name, scope string
}

func (s *Store) LockSSHHostSetup(ctx context.Context, team, hostname string) (*SSHHostSetupState, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname || !opaqueid.Valid(team, opaqueid.TeamPrefix) {
		return nil, sshHostSetupStateError(errors.New("invalid SSH setup scope"))
	}
	serverHash := sha256.Sum256([]byte(s.controlEndpoint))
	scopeBytes, _ := json.Marshal([]string{team, hostname})
	scopeHash := sha256.Sum256(scopeBytes)
	dir, err := privateSubdir(s.database.root, "ssh-host-setups")
	if err == nil {
		dir, err = privateSubdir(dir, hex.EncodeToString(serverHash[:]))
	}
	if err != nil {
		return nil, sshHostSetupStateError(err)
	}
	name := hex.EncodeToString(scopeHash[:])
	lock, err := openLockContext(ctx, filepath.Join(dir, name+".lock"), "SSH host setup")
	if err != nil {
		return nil, sshHostSetupStateError(err)
	}
	info, err := os.Lstat(dir)
	if err == nil {
		err = validatePrivateFile(info, true)
	}
	if err != nil {
		lock.Close()
		return nil, sshHostSetupStateError(err)
	}
	root, err := os.OpenRoot(dir)
	if err == nil {
		var opened os.FileInfo
		opened, err = root.Stat(".")
		if err == nil && !os.SameFile(info, opened) {
			err = errors.New("SSH setup directory changed")
		}
	}
	if err != nil {
		if root != nil {
			root.Close()
		}
		lock.Close()
		return nil, sshHostSetupStateError(err)
	}
	return &SSHHostSetupState{store: s, root: root, lock: lock, name: name + ".sealed", scope: "ssh-host-setup-v1:" + name}, nil
}

func (s *SSHHostSetupState) Close() error { return errors.Join(s.root.Close(), s.lock.Close()) }

func (s *SSHHostSetupState) Read(ctx context.Context) ([]byte, bool, error) {
	info, err := s.root.Lstat(s.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err == nil {
		err = validatePrivateFile(info, false)
	}
	if err != nil {
		return nil, true, sshHostSetupStateError(err)
	}
	file, err := s.root.Open(s.name)
	if err != nil {
		return nil, true, sshHostSetupStateError(err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err == nil && !os.SameFile(info, opened) {
		err = errors.New("SSH setup file changed")
	}
	if err == nil {
		err = validatePrivateFile(opened, false)
	}
	if err != nil {
		return nil, true, sshHostSetupStateError(err)
	}
	sealed, err := io.ReadAll(io.LimitReader(file, maxSSHHostSetupState+1024))
	if err != nil || len(sealed) >= maxSSHHostSetupState+1024 {
		return nil, true, sshHostSetupStateError(errors.Join(err, errors.New("invalid SSH setup size")))
	}
	value, err := s.store.secrets.Open(ctx, s.scope, sealed)
	if err == nil && len(value) > maxSSHHostSetupState {
		err = errors.New("invalid SSH setup size")
	}
	return value, true, sshHostSetupStateError(err)
}

// Save publishes ciphertext only, with file and directory sync before success.
// an interrupted write leaves the previous complete document available.
func (s *SSHHostSetupState) Save(ctx context.Context, value []byte) error {
	if len(value) == 0 || len(value) > maxSSHHostSetupState {
		return sshHostSetupStateError(errors.New("invalid SSH setup size"))
	}
	if info, err := s.root.Lstat(s.name); err == nil {
		if err := validatePrivateFile(info, false); err != nil {
			return sshHostSetupStateError(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return sshHostSetupStateError(err)
	}
	sealed, err := s.store.secrets.Seal(ctx, s.scope, value)
	if err != nil {
		return sshHostSetupStateError(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return sshHostSetupStateError(err)
	}
	temporary := ".pending-" + hex.EncodeToString(nonce[:])
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return sshHostSetupStateError(err)
	}
	defer s.root.Remove(temporary)
	_, writeErr := io.Copy(file, bytes.NewReader(sealed))
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return sshHostSetupStateError(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.root.Rename(temporary, s.name); err != nil {
		return sshHostSetupStateError(err)
	}
	directory, err := s.root.Open(".")
	if err != nil {
		return sshHostSetupStateError(err)
	}
	return sshHostSetupStateError(errors.Join(directory.Sync(), directory.Close()))
}

func sshHostSetupStateError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return failure.Wrap("persist private SSH host setup", failure.ClientStateUnavailable, err)
}
