package publisherjob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func testOptions(t *testing.T) OpenOptions {
	t.Helper()
	owner := os.Geteuid()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return OpenOptions{Root: filepath.Join(parent, "system"), TestOwnerUID: &owner}
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := Open(t.Context(), testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func fixture(t *testing.T, name string) (Job, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey) {
	t.Helper()
	id := func(prefix string) string {
		result, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	job := Job{Kind: KindPublicURL, ID: name, Server: "https://control.example", PublisherID: id(opaqueid.PublisherIdentityPrefix), GrantID: id(opaqueid.PublisherGrantPrefix), PublicURLID: id(opaqueid.PublicURLPrefix), Target: "http://127.0.0.1:3000", Protocol: config.ProtocolHTTP}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: job.PublisherID, GrantId: job.GrantID, KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: "team", Kind: "saved_url", PublicUrlId: &job.PublicURLID}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return job, identity, private
}

func TestRegistryRestartAndScopeBinding(t *testing.T) {
	options := testOptions(t)
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	job, identity, private := fixture(t, "web")
	job.Target, job.TargetTLSName = "https://127.0.0.1:3000", "web.internal"
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || !jobs[0].Enabled || jobs[0].TargetTLSName != "web.internal" {
		t.Fatalf("restart: %+v, %v", jobs, err)
	}
	loaded, key, _, err := r.signingIdentity(t.Context(), jobs[0])
	if err != nil || loaded.GrantId != identity.GrantId || !bytes.Equal(key, private) {
		t.Fatalf("restored signing key: %v", err)
	}
	for _, mutate := range []func(*Job){
		func(j *Job) { j.Server = "https://other.example" },
		func(j *Job) { j.ID = "other" },
		func(j *Job) { j.GrantID, _ = opaqueid.New(opaqueid.PublisherGrantPrefix) },
		func(j *Job) { j.PublicURLID, _ = opaqueid.New(opaqueid.PublicURLPrefix) },
	} {
		changed := jobs[0]
		mutate(&changed)
		if _, _, _, err := r.signingIdentity(t.Context(), changed); !errors.Is(err, ErrScope) {
			t.Fatalf("cross-scope key accepted: %v", err)
		}
	}
	for _, path := range []string{clientstate.DatabasePath(r.Root()), clientstate.DatabasePath(r.Root()) + "-wal"} {
		value, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(value, private) || bytes.Contains(value, []byte(job.Target)) || bytes.Contains(value, []byte(job.TargetTLSName)) {
			t.Fatal("private job state stored in plaintext")
		}
	}
}

func TestRegistryConcurrentProcessesDoNotLoseJobs(t *testing.T) {
	options := testOptions(t)
	first, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 12 {
		job, identity, private := fixture(t, fmt.Sprintf("job-%d", i))
		wg.Go(func() {
			r, err := Open(t.Context(), options)
			if err != nil {
				errs <- err
				return
			}
			defer r.Close()
			errs <- r.Install(t.Context(), job, identity, private)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := first.List(t.Context())
	if err != nil || len(jobs) != 12 {
		t.Fatalf("concurrent registry: %d jobs, %v", len(jobs), err)
	}
	if err := first.Stop(t.Context(), jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := first.signingIdentity(t.Context(), jobs[0]); err != nil {
		t.Fatalf("stop removed the grant/key: %v", err)
	}
	if err := first.Start(t.Context(), jobs[0].ID); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRetryRefreshesSettingsWithoutReplacingScopeOrKey(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := fixture(t, "one")
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	job.Target = "http://127.0.0.1:4000"
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatalf("installation retry failed: %v", err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].Target != job.Target || jobs[0].Revision != 2 {
		t.Fatalf("refreshed settings: %+v, %v", jobs, err)
	}
	_, restored, _, err := r.signingIdentity(t.Context(), jobs[0])
	if err != nil || !bytes.Equal(restored, private) {
		t.Fatalf("retry replaced signing key: %v", err)
	}
	_, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(t.Context(), job, identity, replacement); !errors.Is(err, ErrScope) {
		t.Fatalf("replacement key accepted: %v", err)
	}
	job.Server = "https://another.example"
	if err := r.Install(t.Context(), job, identity, private); !errors.Is(err, ErrScope) {
		t.Fatalf("replacement server scope accepted: %v", err)
	}
}

func TestStableJobKeyAndDisplayName(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := fixture(t, "placeholder")
	if PublicURLJobKey(job.Server+"/", job.PublicURLID) != PublicURLJobKey(job.Server, job.PublicURLID) {
		t.Fatal("server spelling changed the stable job key")
	}
	job.ID = PublicURLJobKey(job.Server, job.PublicURLID)
	if job.ID == PrivateServiceJobKey(job.Server, job.PublicURLID) {
		t.Fatal("different resource kinds share a job key")
	}
	job.Name = "first"
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	job.Name = "renamed"
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID || jobs[0].Name != "renamed" || jobs[0].Revision != 2 {
		t.Fatalf("renamed job: %+v %v", jobs, err)
	}
	if err := r.Stop(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.status(t.Context(), job.ID, 3, Status{State: "stopped"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	jobs, err = r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("removed job: %+v %v", jobs, err)
	}
	if _, found, _, err := r.signingIdentity(t.Context(), job); err == nil || found != nil {
		t.Fatalf("removed job identity still readable: %v", err)
	}
}

func TestResolveJobNameOrIDWithoutCrossProjectGuessing(t *testing.T) {
	r := testRegistry(t)
	first, identity, private := fixture(t, "first")
	first.Name = "orders"
	if err := r.Install(t.Context(), first, identity, private); err != nil {
		t.Fatal(err)
	}
	if selected, err := r.ResolveJob(t.Context(), "orders"); err != nil || selected.ID != first.ID {
		t.Fatalf("single service name: %+v %v", selected, err)
	}
	second, identity, private := fixture(t, "second")
	second.Name = "orders"
	second.Server = "https://other.example"
	if err := r.Install(t.Context(), second, identity, private); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveJob(t.Context(), "orders"); !errors.Is(err, ErrJobAmbiguous) {
		t.Fatalf("same name across projects was selected: %v", err)
	}
	for _, id := range []string{first.ID, second.ID} {
		selected, err := r.ResolveJob(t.Context(), id)
		if err != nil || selected.ID != id {
			t.Fatalf("exact job ID could not disambiguate: %+v %v", selected, err)
		}
	}
	if _, err := r.ResolveJob(t.Context(), "missing"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("missing job matched: %v", err)
	}
}

func TestRegistryRejectsUnsafeAndReplacedState(t *testing.T) {
	for _, part := range []string{"key", "database", "root", "lock"} {
		for _, change := range []string{"missing", "symlink", "mode", "replacement"} {
			t.Run(part+"/"+change, func(t *testing.T) {
				r := testRegistry(t)
				path := map[string]string{"key": clientstate.WrappingKeyPath(r.Root()), "database": clientstate.DatabasePath(r.Root()), "root": r.Root(), "lock": filepath.Join(r.Root(), "jobs.lock")}[part]
				switch change {
				case "missing":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".old", path); err != nil {
						t.Fatal(err)
					}
				case "mode":
					if err := os.Chmod(path, 0o777); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if part == "root" {
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					} else {
						value, err := os.ReadFile(path + ".old")
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, value, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if _, err := r.List(t.Context()); !errors.Is(err, ErrUnsafeState) {
					t.Fatalf("unsafe state accepted: %v", err)
				}
			})
		}
	}
}

func TestMissingOrChangedKeyFailsAcrossReopen(t *testing.T) {
	for _, change := range []string{"missing", "wrong", "missing database"} {
		t.Run(change, func(t *testing.T) {
			options := testOptions(t)
			r, err := Open(t.Context(), options)
			if err != nil {
				t.Fatal(err)
			}
			job, identity, private := fixture(t, "one")
			if err := r.Install(t.Context(), job, identity, private); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if change == "wrong" {
				err = os.WriteFile(clientstate.WrappingKeyPath(options.Root), bytes.Repeat([]byte{1}, 32), 0o600)
			} else {
				path := clientstate.WrappingKeyPath(options.Root)
				if change == "missing database" {
					path = clientstate.DatabasePath(options.Root)
				}
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(t.Context(), options); err == nil {
				reopened.Close()
				t.Fatal("state was recreated with a lost/replaced key or database")
			}
		})
	}
}

func TestSameContentReplacementIsRejectedAfterRestart(t *testing.T) {
	for _, part := range []string{"key", "database", "lock"} {
		t.Run(part, func(t *testing.T) {
			options := testOptions(t)
			r, err := Open(t.Context(), options)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			path := map[string]string{"key": clientstate.WrappingKeyPath(options.Root), "database": clientstate.DatabasePath(options.Root), "lock": filepath.Join(options.Root, "jobs.lock")}[part]
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			value, err := os.ReadFile(path + ".old")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, value, 0o600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(t.Context(), options); !errors.Is(err, ErrUnsafeState) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatalf("replacement accepted on boot: %v", err)
			}
		})
	}
}

func TestOpenRejectsSymlinkAncestorsBeforeCreatingState(t *testing.T) {
	options := testOptions(t)
	link := filepath.Join(filepath.Dir(options.Root), "linked")
	if err := os.Symlink(filepath.Dir(options.Root), link); err != nil {
		t.Fatal(err)
	}
	physicalRoot := options.Root
	options.Root = filepath.Join(link, "system")
	if r, err := Open(t.Context(), options); !errors.Is(err, ErrUnsafeState) {
		if r != nil {
			r.Close()
		}
		t.Fatalf("symlink ancestor accepted: %v", err)
	}
	if _, err := os.Lstat(physicalRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe state path was initialized: %v", err)
	}
}

func TestRegistryRejectsNamespaceAndInvalidJob(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := fixture(t, "one")
	identity.Kind = "namespace"
	if err := r.Install(t.Context(), job, identity, private); !errors.Is(err, ErrScope) {
		t.Fatalf("namespace job: %v", err)
	}
	identity.Kind = "saved_url"
	job.Server = ""
	if err := r.Install(t.Context(), job, identity, private); !errors.Is(err, ErrScope) {
		t.Fatalf("implicit server: %v", err)
	}
	otherOwner := os.Geteuid() + 1
	if _, err := Open(context.Background(), OpenOptions{Root: r.Root(), TestOwnerUID: &otherOwner}); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("unsafe owner accepted: %v", err)
	}
}
