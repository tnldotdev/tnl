package publisherjob

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openOwned(filepath.Join(base, "publisher"), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testJob(t *testing.T, id string) Job {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Job{Server: "https://control.example.com", Target: "http://127.0.0.1:3000", Private: key,
		Identity: authorityv1.PublisherEnrollmentResult{Kind: "saved_url", PublicUrlId: &id}}
}

func TestSealedJobsRestartAndScope(t *testing.T) {
	s := testStore(t)
	first := testJob(t, "url-first")
	second := testJob(t, "url-second")
	if err := s.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(second); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(first); !errors.Is(err, os.ErrExist) {
		t.Fatalf("duplicate job replaced signing key: %v", err)
	}
	sealed, err := os.ReadFile(filepath.Join(s.root, jobName(first.Server, first.ID())))
	if err != nil || bytes.Contains(sealed, first.Private) || bytes.Contains(sealed, []byte(first.Target)) {
		t.Fatal("job contains plaintext private state")
	}
	restarted, err := openOwned(s.root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := restarted.List()
	if err != nil || len(jobs) != 2 {
		t.Fatalf("restart lost jobs: %v, %v", jobs, err)
	}
	for _, job := range jobs {
		proof, err := publisheridentity.SignRun(job.Private, job.ID(), "new-run")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisheridentity.VerifyRun(job.Private.Public().(ed25519.PublicKey), proof, job.ID(), "new-run"); err != nil {
			t.Fatal(err)
		}
		if _, err := publisheridentity.VerifyRun(job.Private.Public().(ed25519.PublicKey), proof, "other-url", "new-run"); err == nil {
			t.Fatal("proof escaped its saved URL scope")
		}
	}
	if err := restarted.Remove(first.Server, first.ID()); err != nil {
		t.Fatal(err)
	}
	remaining, err := restarted.List()
	if err != nil || len(remaining) != 1 || remaining[0].ID() != second.ID() {
		t.Fatalf("stop affected another job: %v, %v", remaining, err)
	}
	if err := os.Remove(filepath.Join(s.root, "wrapping-key-v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := openOwned(s.root, uint32(os.Geteuid())); err == nil {
		t.Fatal("recreated missing wrapping key")
	}
}

func TestJobStateRejectsUnsafeFiles(t *testing.T) {
	s := testStore(t)
	j := testJob(t, "url-private")
	if err := s.Add(j); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, jobName(j.Server, j.ID()))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("accepted group-readable job")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(s.root, "wrapping-key-v1"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("followed job symlink")
	}
	if err := os.Chmod(s.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openOwned(s.root, uint32(os.Geteuid())); err == nil {
		t.Fatal("accepted shared state directory")
	}
}
