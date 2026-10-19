// package publisherjob owns installed publications and their private state.
package publisherjob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	ErrUnsafeState  = failure.Wrap("open installed publisher state", failure.ClientStateUnavailable, errors.New("installed publisher state is unsafe or has changed"))
	ErrScope        = failure.Wrap("select installed job", failure.InvalidTunnelFlags, errors.New("installed publishers require an explicit server and an exact public URL or private-service grant; connectors require a saved user identity"))
	ErrJobExists    = failure.Wrap("install publication", failure.ServerConflict, errors.New("saved publication is already installed"))
	ErrJobNotFound  = failure.Wrap("read installed publication", failure.ServerResourceNotFound, errors.New("installed publisher job does not exist"))
	ErrJobAmbiguous = failure.Wrap("select installed publication", failure.InstalledJobAmbiguous, errors.New("more than one installed job has this name"))
)

const registryName = "publisher-jobs-v1"

type OpenOptions struct {
	Root string
	User bool
	// tests must explicitly select their uid for isolated system state.
	TestOwnerUID *int
}

type Kind string

const (
	// the empty public URL kind preserves existing installed state.
	KindPublicURL      Kind = ""
	KindPrivateService Kind = "private"
	KindConnector      Kind = "connector"
	KindGroup          Kind = "group"
)

type Job struct {
	GroupMember      *controlv1.PublisherGroupMember `json:"group_member,omitempty"`
	GroupInstance    string                          `json:"group_instance,omitempty"`
	IdentityDir      string                          `json:"identity_dir,omitempty"`
	Kind             Kind                            `json:"kind,omitempty"`
	PrivateServiceID string                          `json:"private_service_id,omitempty"`
	TrustRevision    int64                           `json:"trust_revision,omitempty"`
	PublisherPool    bool                            `json:"publisher_pool,omitempty"`
	IdentityID       string                          `json:"identity_id,omitempty"`
	StateDir         string                          `json:"state_dir,omitempty"`
	Project          *projectconfig.Project          `json:"project,omitempty"`
	ProjectService   string                          `json:"project_service,omitempty"`
	Trust            *privatetrust.Snapshot          `json:"trust,omitempty"`
	ManagedTLS       *controlv1.ManagedServiceTLS    `json:"managed_tls,omitempty"`
	ID               string                          `json:"job_id"`
	Name             string                          `json:"name,omitempty"`
	Server           string                          `json:"server"`
	PublisherID      string                          `json:"publisher_id"`
	GrantID          string                          `json:"grant_id"`
	PublicURLID      string                          `json:"public_url_id"`
	Target           string                          `json:"target"`
	Protocol         config.ProtocolName             `json:"protocol"`
	TargetTLSName    string                          `json:"target_tls_name,omitempty"`
	// trust is captured at install time, so boot never depends on a user's files.
	TargetCAPEM []byte                      `json:"target_ca_pem,omitempty"`
	ServerCAPEM []byte                      `json:"server_ca_pem,omitempty"`
	Limits      publisher.ApplicationLimits `json:"limits"`
	Enabled     bool                        `json:"enabled"`
	Revision    uint64                      `json:"revision"`
	Status      Status                      `json:"status"`
}

// String keeps private key material out of incidental diagnostic formatting.
func (j Job) String() string {
	type plain Job
	return fmt.Sprintf("%+v", plain(j))
}

func (j Job) GoString() string { return j.String() }

// status contains approved observations only; errors and tokens never enter it.
type Status struct {
	ObservedRevision int64  `json:"observed_revision,omitempty"`
	State            string `json:"state"`
	Failure          string `json:"failure,omitempty"`
	Attempts         uint64 `json:"attempts,omitempty"`
	PublishRunNumber uint64 `json:"publish_run_number,omitempty"`
}

type Registry struct {
	mu       sync.Mutex
	database *clientstate.Database
	root     string
	owner    int
	user     bool
	pins     map[string]os.FileInfo
	key      []byte
}

// Open uses a standalone database and file wrapping key, including on macOS.
func Open(ctx context.Context, options OpenOptions) (*Registry, error) {
	owner := 0
	if options.User {
		owner = os.Getuid()
	}
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
	r := &Registry{database: db, root: db.Root(), owner: owner, user: options.User, pins: map[string]os.FileInfo{}}
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
				if existing.Server != job.Server || existing.PublisherID != job.PublisherID || existing.GrantID != job.GrantID || existing.PublicURLID != job.PublicURLID || existing.PrivateServiceID != job.PrivateServiceID || existing.Kind != job.Kind {
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
			if existing.Server == job.Server && existing.Kind == job.Kind && (job.PublicURLID != "" && existing.PublicURLID == job.PublicURLID || job.PrivateServiceID != "" && existing.PrivateServiceID == job.PrivateServiceID) {
				return ErrJobExists
			}
			// independently supervised jobs need independent runtime identities.
			// one group job may publish many services with its one replica identity.
			if existing.Server == job.Server && existing.PublisherID == job.PublisherID {
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
		public, err := json.Marshal(identity)
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

// JobKey keeps the resource kind in the key, so a future private service ID
// cannot collide with a public URL ID on the same server.
func JobKey(server, kind, resourceID string) string {
	if canonical, err := clientstate.CanonicalServer(server); err == nil {
		server = canonical
	}
	digest := sha256.Sum256([]byte(server + "\x00" + kind + "\x00" + resourceID))
	return kind + "-" + hex.EncodeToString(digest[:12])
}

func PublicURLJobKey(server, publicURLID string) string {
	return JobKey(server, "url", publicURLID)
}

func PrivateServiceJobKey(server, privateServiceID string) string {
	return JobKey(server, "private", privateServiceID)
}

// Remove drops local desired state and its job-scoped signing identity after
// the caller has stopped and joined the worker.
func (r *Registry) Remove(ctx context.Context, id string) error {
	return r.update(ctx, func(jobs *[]Job) error {
		for i, job := range *jobs {
			if job.ID != id {
				continue
			}
			if job.Enabled || job.Status.State != "stopped" {
				return ErrScope
			}
			if job.Kind != KindConnector && job.Kind != KindGroup {
				profile, err := r.database.Server(ctx, job.Server)
				if err != nil {
					return err
				}
				if err := profile.RemovePublisherSigningIdentity(ctx, "job:"+id); err != nil {
					return err
				}
			}
			*jobs = append((*jobs)[:i], (*jobs)[i+1:]...)
			return nil
		}
		return ErrJobNotFound
	})
}

func matches(job Job, identity authorityv1.PublisherEnrollmentResult) bool {
	if identity.TeamId == "" || identity.ClientId != job.PublisherID || identity.GrantId != job.GrantID || !opaqueid.Valid(identity.KeyId, opaqueid.PublisherIdentityKeyPrefix) {
		return false
	}
	switch job.Kind {
	case KindPrivateService:
		return identity.Kind == authorityv1.PrivateService && identity.PrivateServiceId != nil && *identity.PrivateServiceId == job.PrivateServiceID && identity.PublicUrlId == nil && identity.Namespace == nil && identity.DomainId == nil
	case KindPublicURL:
		return identity.Kind == authorityv1.SavedUrl && identity.PublicUrlId != nil && *identity.PublicUrlId == job.PublicURLID && identity.PrivateServiceId == nil && identity.Namespace == nil && identity.DomainId == nil
	default:
		return false
	}
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
	var identity authorityv1.PublisherEnrollmentResult
	if !found || json.Unmarshal(saved.PublicValue, &identity) != nil || saved.ID != job.PublisherID || !matches(job, identity) || len(saved.PrivateValue) != ed25519.PrivateKeySize {
		return identity, nil, nil, ErrScope
	}
	return identity, ed25519.PrivateKey(saved.PrivateValue), profile, nil
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

// ResolveJob requires an unambiguous ID or display name across all installed
// projects in this supervisor. no job changes before this selection succeeds.
func (r *Registry) ResolveJob(ctx context.Context, selected string) (Job, error) {
	jobs, err := r.List(ctx)
	if err != nil {
		return Job{}, err
	}
	var match Job
	count := 0
	for _, job := range jobs {
		if selected == job.ID || selected != "" && selected == job.Name {
			match = job
			count++
		}
	}
	if count > 1 {
		return Job{}, ErrJobAmbiguous
	}
	if count == 0 {
		return Job{}, ErrJobNotFound
	}
	return match, nil
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
	if !naming.ValidServiceName(job.ID) || len(job.Name) > 128 || strings.TrimSpace(job.Name) != job.Name || strings.ContainsAny(job.Name, "\x00\r\n") || job.Server == "" {
		return ErrScope
	}
	if job.Kind != KindGroup && job.GroupMember != nil ||
		job.Kind != KindGroup && job.GroupInstance != "" ||
		job.Kind != KindGroup && job.IdentityDir != "" ||
		job.Kind != KindConnector && (job.IdentityID != "" || job.StateDir != "") ||
		job.Kind != KindPrivateService && (job.Project != nil || job.ProjectService != "" || job.PublisherPool) ||
		(job.Kind == KindPublicURL || job.Kind == KindGroup) && (job.Trust != nil || job.TrustRevision != 0) {
		return ErrScope
	}
	switch job.Kind {
	case KindGroup:
		if !naming.ValidServiceName(job.GroupInstance) {
			return ErrScope
		}
		if job.IdentityDir != "" && (!filepath.IsAbs(job.IdentityDir) || filepath.Clean(job.IdentityDir) != job.IdentityDir) {
			return ErrScope
		}
		if job.GroupMember == nil || job.GroupMember.PublisherIdentityId != job.PublisherID ||
			job.GroupMember.GroupName == "local" || !naming.ValidServiceName(job.GroupMember.GroupName) ||
			!opaqueid.Valid(job.PublisherID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.GroupMember.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
			job.GroupMember.TeamId == "" || job.GroupMember.GroupId == "" || job.GroupMember.ProjectKey == "" ||
			job.PrivateServiceID != "" || job.PublicURLID != "" || job.Target != "" || job.GrantID != "" || job.Protocol != "" ||
			job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 || job.Limits != (publisher.ApplicationLimits{}) {
			return ErrScope
		}
	case KindConnector:
		if !opaqueid.Valid(job.PrivateServiceID, opaqueid.PrivateServicePrefix) || job.PublicURLID != "" || job.PublisherID != "" || job.GrantID != "" ||
			!opaqueid.Valid(job.IdentityID, opaqueid.IdentityPrefix) || !filepath.IsAbs(job.StateDir) || job.TrustRevision < 1 ||
			job.Limits != (publisher.ApplicationLimits{}) || !job.Protocol.Valid() {
			return ErrScope
		}
	case KindPrivateService, KindPublicURL:
		if !opaqueid.Valid(job.PublisherID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.GrantID, opaqueid.PublisherGrantPrefix) {
			return ErrScope
		}
		if job.Kind == KindPrivateService {
			if !opaqueid.Valid(job.PrivateServiceID, opaqueid.PrivateServicePrefix) || job.PublicURLID != "" || job.TrustRevision < 1 || !job.Protocol.Valid() || job.Project == nil && job.ProjectService != "" {
				return ErrScope
			}
		} else if !opaqueid.Valid(job.PublicURLID, opaqueid.PublicURLPrefix) || job.Protocol != config.ProtocolHTTP || job.PrivateServiceID != "" {
			return ErrScope
		}
	default:
		return ErrScope
	}
	server, err := clientstate.CanonicalServer(job.Server)
	if err != nil {
		return ErrScope
	}
	job.Server = server
	if err := ValidateTrust(job.ServerCAPEM); err != nil {
		return err
	}
	if job.Kind == KindGroup {
		return nil
	}
	if err := job.Limits.Validate(); err != nil {
		return ErrScope
	}
	return validateTarget(job)
}

// InstallConnector stores user desired state only. credentials remain in the
// signed-in profile, and the worker checks the exact identity at every start.
func (r *Registry) InstallConnector(ctx context.Context, job Job) error {
	if !r.user || job.Kind != KindConnector {
		return ErrScope
	}
	if err := validateJob(&job); err != nil {
		return err
	}
	return r.update(ctx, func(jobs *[]Job) error {
		for i, existing := range *jobs {
			if existing.ID == job.ID {
				if existing.Kind != KindConnector || existing.Server != job.Server || existing.IdentityID != job.IdentityID || existing.PrivateServiceID != job.PrivateServiceID {
					return ErrScope
				}
				job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: "starting"}
				(*jobs)[i] = job
				return nil
			}
		}
		if len(*jobs) >= 1024 {
			return ErrScope
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: "starting"}
		*jobs = append(*jobs, job)
		return nil
	})
}
