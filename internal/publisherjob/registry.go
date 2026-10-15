// package publisherjob owns enrolled system publications and their private state.
package publisherjob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	ErrUnsafeState = failure.Wrap("open system publisher state", failure.ClientStateUnavailable, errors.New("system publisher state is unsafe or has changed"))
	ErrScope       = failure.Wrap("select system publication", failure.InvalidTunnelFlags, errors.New("a system job requires an explicit server and a saved URL grant"))
	ErrJobExists   = failure.Wrap("install system publication", failure.ServerConflict, errors.New("job name or saved URL is already installed"))
	ErrJobNotFound = failure.Wrap("read system publication", failure.ServerResourceNotFound, errors.New("system publisher job does not exist"))
)

const registryName = "publisher-jobs-v1"

type OpenOptions struct {
	Root string
	// production state is root-owned. tests must explicitly select their uid.
	TestOwnerUID *int
}

type Job struct {
	ID            string                             `json:"job_id"`
	Server        string                             `json:"server"`
	PublisherID   string                             `json:"publisher_id"`
	GrantID       string                             `json:"grant_id"`
	PublicURLID   string                             `json:"public_url_id"`
	Target        string                             `json:"target"`
	Protocol      controlv1.PublicURLServiceProtocol `json:"protocol"`
	TargetTLS     bool                               `json:"target_tls"`
	TargetTLSName string                             `json:"target_tls_name,omitempty"`
	// trust is captured at install time, so boot never depends on a user's files.
	TargetCAPEM []byte                      `json:"target_ca_pem,omitempty"`
	ServerCAPEM []byte                      `json:"server_ca_pem,omitempty"`
	Limits      publisher.ApplicationLimits `json:"limits"`
	Enabled     bool                        `json:"enabled"`
	Revision    uint64                      `json:"revision"`
	Status      Status                      `json:"status"`
}

// status contains approved observations only; errors and tokens never enter it.
type Status struct {
	State            string `json:"state"`
	Failure          string `json:"failure,omitempty"`
	Attempts         uint64 `json:"attempts,omitempty"`
	PublishRunNumber uint64 `json:"publish_run_number,omitempty"`
}

type identityBinding struct {
	JobID    string                                `json:"job_id"`
	Server   string                                `json:"server"`
	Identity authorityv1.PublisherEnrollmentResult `json:"identity"`
}

type Registry struct {
	mu       sync.Mutex
	database *clientstate.Database
	root     string
	owner    int
	pins     map[string]os.FileInfo
	key      []byte
}

// Open uses a standalone database and file wrapping key, including on macOS.
func Open(ctx context.Context, options OpenOptions) (*Registry, error) {
	owner := 0
	if options.TestOwnerUID != nil {
		owner = *options.TestOwnerUID
	}
	if owner < 0 || os.Geteuid() != owner || !filepath.IsAbs(options.Root) {
		return nil, ErrUnsafeState
	}
	root := filepath.Clean(options.Root)
	if err := trustedStatePath(root, owner); err != nil {
		return nil, err
	}
	// an initialized registry must never be silently recreated after deletion.
	if _, err := os.Lstat(clientstate.DatabasePath(root)); errors.Is(err, os.ErrNotExist) {
		for _, path := range []string{clientstate.WrappingKeyPath(root), filepath.Join(root, "jobs.lock")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return nil, ErrUnsafeState
			}
		}
	}
	if info, err := os.Lstat(root); err == nil {
		if !privateInfo(info, owner, true) {
			return nil, ErrUnsafeState
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnsafeState
	}
	db, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return nil, err
	}
	r := &Registry{database: db, root: db.Root(), owner: owner, pins: map[string]os.FileInfo{}}
	// pin the registry lock before any reader or writer can use it.
	lock, err := filelock.AcquireContext(ctx, filepath.Join(r.root, "jobs.lock"), owner)
	if err == nil {
		err = r.pin()
		if err == nil {
			err = r.verifyManifest(ctx)
		}
		err = errors.Join(err, lock.Close())
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return r, nil
}

func (r *Registry) Close() error { return r.database.Close() }
func (r *Registry) Root() string { return r.root }

// Profile lets enrollment save its key before redeeming a one-use secret.
func (r *Registry) Profile(ctx context.Context, server string) (*clientstate.Store, error) {
	if server == "" {
		return nil, ErrScope
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return r.database.Server(ctx, server)
}

// Install binds a key to this job, server, and exact grant. a failed registry
// write can leave an unused encrypted key, but cannot publish a partial job.
func (r *Registry) Install(ctx context.Context, job Job, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) error {
	if err := validateJob(&job); err != nil {
		return err
	}
	if !matches(job, identity) || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:32]), private) {
		return ErrScope
	}
	return r.update(ctx, func(jobs *[]Job) error {
		for i, existing := range *jobs {
			if existing.ID == job.ID {
				if existing.Server != job.Server || existing.PublisherID != job.PublisherID || existing.GrantID != job.GrantID || existing.PublicURLID != job.PublicURLID {
					return ErrScope
				}
				loaded, key, _, err := r.signingIdentity(ctx, existing)
				if err != nil {
					return err
				}
				before, _ := json.Marshal(loaded)
				after, _ := json.Marshal(identity)
				if !bytes.Equal(key, private) || !bytes.Equal(before, after) {
					return ErrScope
				}
				// retrying installation may refresh local settings, but cannot replace
				// its signing key or grant. reconciliation joins the old worker first.
				job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: "starting"}
				(*jobs)[i] = job
				return nil
			}
			if existing.Server == job.Server && existing.PublicURLID == job.PublicURLID {
				return ErrJobExists
			}
		}
		if len(*jobs) >= 1024 {
			return ErrScope
		}
		profile, err := r.database.Server(ctx, job.Server)
		if err != nil {
			return err
		}
		public, err := json.Marshal(identityBinding{JobID: job.ID, Server: job.Server, Identity: identity})
		if err != nil {
			return err
		}
		if err := profile.SavePublisherSigningIdentity(ctx, "job:"+job.ID, clientstate.PublisherSigningIdentity{ID: identity.ClientId, PublicValue: public, PrivateValue: private}); err != nil {
			return err
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: "starting"}
		*jobs = append(*jobs, job)
		return nil
	})
}

func matches(job Job, identity authorityv1.PublisherEnrollmentResult) bool {
	return identity.Kind == "saved_url" && identity.PublicUrlId != nil && *identity.PublicUrlId == job.PublicURLID && identity.TeamId != "" && identity.ClientId == job.PublisherID && identity.GrantId == job.GrantID && opaqueid.Valid(identity.KeyId, opaqueid.PublisherIdentityKeyPrefix)
}

func (r *Registry) signingIdentity(ctx context.Context, job Job) (authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, *clientstate.Store, error) {
	if err := r.validate(); err != nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, nil, err
	}
	profile, err := r.database.Server(ctx, job.Server)
	if err != nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, nil, err
	}
	saved, found, err := profile.PublisherSigningIdentity(ctx, "job:"+job.ID)
	if err != nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, nil, err
	}
	var binding identityBinding
	if !found || json.Unmarshal(saved.PublicValue, &binding) != nil || binding.JobID != job.ID || binding.Server != job.Server || saved.ID != job.PublisherID || !matches(job, binding.Identity) || len(saved.PrivateValue) != ed25519.PrivateKeySize {
		return binding.Identity, nil, nil, ErrScope
	}
	return binding.Identity, ed25519.PrivateKey(saved.PrivateValue), profile, nil
}

func (r *Registry) Start(ctx context.Context, id string) error { return r.setEnabled(ctx, id, true) }

// Stop changes only local desired state. it never revokes a server grant.
func (r *Registry) Stop(ctx context.Context, id string) error { return r.setEnabled(ctx, id, false) }

func (r *Registry) setEnabled(ctx context.Context, id string, enabled bool) error {
	return r.update(ctx, func(jobs *[]Job) error {
		for i := range *jobs {
			j := &(*jobs)[i]
			if j.ID != id {
				continue
			}
			if j.Enabled == enabled && !enabled {
				return nil
			}
			j.Enabled = enabled
			j.Revision++
			j.Status = Status{State: "stopping"}
			if enabled {
				j.Status.State = "starting"
			}
			return nil
		}
		return ErrJobNotFound
	})
}

func (r *Registry) List(ctx context.Context) (jobs []Job, err error) {
	err = r.locked(ctx, func() error { jobs, err = r.load(ctx); return err })
	return jobs, err
}

func (r *Registry) status(ctx context.Context, id string, revision uint64, status Status) error {
	return r.update(ctx, func(jobs *[]Job) error {
		for i := range *jobs {
			if (*jobs)[i].ID == id && (*jobs)[i].Revision == revision {
				(*jobs)[i].Status = status
				return nil
			}
		}
		return nil // an observation from replaced work must not overwrite new state.
	})
}

func (r *Registry) update(ctx context.Context, change func(*[]Job) error) error {
	return r.locked(ctx, func() error {
		jobs, err := r.load(ctx)
		if err != nil {
			return err
		}
		if err := change(&jobs); err != nil {
			return err
		}
		slices.SortFunc(jobs, func(a, b Job) int { return bytes.Compare([]byte(a.ID), []byte(b.ID)) })
		value, err := json.Marshal(jobs)
		if err != nil {
			return err
		}
		if err := r.validate(); err != nil {
			return err
		}
		// one SQLite statement atomically replaces the authenticated snapshot.
		return r.database.SaveSystemState(ctx, registryName, value)
	})
}

func (r *Registry) load(ctx context.Context) ([]Job, error) {
	value, found, err := r.database.SystemState(ctx, registryName)
	if err != nil || !found {
		return nil, err
	}
	var jobs []Job
	if json.Unmarshal(value, &jobs) != nil || len(jobs) > 1024 {
		return nil, ErrUnsafeState
	}
	seen := map[string]bool{}
	for i := range jobs {
		original := jobs[i]
		if validateJob(&jobs[i]) != nil || jobs[i].Server != original.Server || jobs[i].Target != original.Target || original.Revision == 0 || seen[original.ID] {
			return nil, ErrUnsafeState
		}
		seen[original.ID] = true
	}
	return jobs, nil
}

func (r *Registry) locked(ctx context.Context, operation func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.validate(); err != nil {
		return err
	}
	lock, err := filelock.AcquireContext(ctx, filepath.Join(r.root, "jobs.lock"), r.owner)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := r.validate(); err != nil {
		return err
	}
	return operation()
}

// WaitStopped waits for the service's joined worker observation after Stop.
func (r *Registry) WaitStopped(ctx context.Context, id string) error {
	for {
		jobs, err := r.List(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, job := range jobs {
			if job.ID == id {
				found = true
				if !job.Enabled && job.Status.State == "stopped" {
					return nil
				}
			}
		}
		if !found {
			return ErrJobNotFound
		}
		if err := wait(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

func validateJob(job *Job) error {
	if !naming.ValidServiceName(job.ID) || job.Server == "" || !opaqueid.Valid(job.PublisherID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.GrantID, opaqueid.PublisherGrantPrefix) || !opaqueid.Valid(job.PublicURLID, opaqueid.PublicURLPrefix) || !job.Protocol.Valid() {
		return ErrScope
	}
	server, err := clientstate.CanonicalServer(job.Server)
	if err != nil {
		return ErrScope
	}
	job.Server = server
	if err := job.Limits.Validate(); err != nil {
		return ErrScope
	}
	return validateTarget(job)
}
