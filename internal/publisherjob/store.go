// Package publisherjob owns sealed, system-owned enrolled publisher jobs.
package publisherjob

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

// Job carries only the scope returned by enrollment and its signing key.
type Job struct {
	Server   string                                `json:"server"`
	Target   string                                `json:"target"`
	Identity authorityv1.PublisherEnrollmentResult `json:"identity"`
	Private  ed25519.PrivateKey                    `json:"private"`
}

func (j Job) ID() string {
	if j.Identity.PublicUrlId == nil {
		return ""
	}
	return *j.Identity.PublicUrlId
}

// Dir is independent of the interactive client state and its macOS keychain.
func Dir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/tnl/publisher"
	}
	return "/var/lib/tnl/publisher"
}

type Store struct {
	root string
	key  []byte
	uid  uint32
}

// Open requires root and rejects non-root-owned or group-accessible state.
func Open(root string) (*Store, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("publisher jobs require root; run with sudo")
	}
	return openOwned(root, 0)
}

func checkOwner(info os.FileInfo, uid uint32, dir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode()&os.ModeSymlink != 0 ||
		(dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("publisher job state must be owner-only, regular, and owned by root")
	}
	return nil
}

func openOwned(root string, uid uint32) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("publisher job state needs an absolute directory")
	}
	// inspect every existing parent before creating anything; never traverse a symlink.
	for p := root; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return nil, errors.New("publisher job state parent is not a directory")
			}
			if p == root && checkOwner(info, uid, true) != nil {
				return nil, errors.New("publisher job state directory must be owner-only")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || checkOwner(info, uid, true) != nil {
		return nil, errors.New("publisher job state directory must be owner-only")
	}
	keyPath := filepath.Join(root, "wrapping-key-v1")
	key, err := readOwned(keyPath, uid, 32)
	if errors.Is(err, os.ErrNotExist) {
		entries, listErr := os.ReadDir(root)
		if listErr != nil {
			return nil, listErr
		}
		if len(entries) != 0 {
			return nil, errors.New("publisher wrapping key is missing; restore it with the jobs")
		}
		key = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		if err = createOwned(keyPath, key); err != nil {
			// another initializer may have won; never replace its key.
			key, err = readOwned(keyPath, uid, 32)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open publisher wrapping key: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("invalid publisher wrapping key length")
	}
	return &Store{root: root, key: key, uid: uid}, nil
}

func readOwned(path string, uid uint32, max int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkOwner(before, uid, false); err != nil || before.Size() > max {
		return nil, errors.New("publisher job file has invalid ownership, mode, or size")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || checkOwner(after, uid, false) != nil || !os.SameFile(before, after) {
		return nil, errors.New("publisher job file changed while opening")
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}

func createOwned(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

func jobName(server, id string) string {
	digest := sha256.Sum256([]byte(server + "\x00" + id))
	return hex.EncodeToString(digest[:]) + ".job"
}

func (s *Store) seal(j Job) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte("tnl publisher job v1\x00"+jobName(j.Server, j.ID()))), nil
}

func (s *Store) open(name string, sealed []byte) (Job, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return Job{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Job{}, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return Job{}, errors.New("invalid sealed publisher job")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte("tnl publisher job v1\x00"+name))
	if err != nil {
		return Job{}, errors.New("cannot decrypt publisher job; restore its wrapping key")
	}
	var job Job
	if err := json.Unmarshal(plain, &job); err != nil || jobName(job.Server, job.ID()) != name || len(job.Private) != ed25519.PrivateKeySize || job.Identity.Kind != "saved_url" || job.ID() == "" {
		return Job{}, errors.New("invalid publisher job scope")
	}
	return job, nil
}

// Add stores a single saved-URL grant; the server is part of the job identity.
func (s *Store) Add(job Job) error {
	server, err := clientstate.CanonicalServer(job.Server)
	if err != nil || server != job.Server || job.Identity.Kind != "saved_url" || job.ID() == "" || len(job.Private) != ed25519.PrivateKeySize || job.Target == "" {
		return errors.New("a background job needs a canonical server, saved URL grant, signing key, and target")
	}
	sealed, err := s.seal(job)
	if err != nil {
		return err
	}
	// write and sync a temporary file, then link it exclusively so a crash
	// cannot expose a partially written job or overwrite another signing key.
	f, err := os.CreateTemp(s.root, ".job-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(sealed); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), filepath.Join(s.root, jobName(job.Server, job.ID()))); err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) List() ([]Job, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var jobs []Job
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".job" {
			continue
		}
		sealed, err := readOwned(filepath.Join(s.root, name), s.uid, 16<<10)
		if err != nil {
			return nil, err
		}
		job, err := s.open(name, sealed)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobName(jobs[i].Server, jobs[i].ID()) < jobName(jobs[j].Server, jobs[j].ID())
	})
	return jobs, nil
}

func (s *Store) Remove(server, id string) error {
	return os.Remove(filepath.Join(s.root, jobName(server, id)))
}
