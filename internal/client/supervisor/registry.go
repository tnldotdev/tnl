// package publisherjob owns installed publications and their private state.
package supervisor

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

	"github.com/tnldotdev/tnl/internal/client/filelock"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var (
	ErrUnsafeState  = failure.Wrap("open installed publisher state", failure.ClientStateUnavailable, errors.New("installed publisher state is unsafe or has changed"))
	ErrScope        = target.ErrScope
	ErrJobExists    = failure.Wrap("install publication", failure.ServerConflict, errors.New("saved publication is already installed"))
	ErrJobNotFound  = failure.Wrap("read installed publication", failure.ServerResourceNotFound, errors.New("installed publisher job does not exist"))
	ErrJobAmbiguous = failure.Wrap("select installed publication", failure.InstalledJobAmbiguous, errors.New("more than one installed job has this name"))
)

type OpenOptions struct {
	Root string
	User bool
	// StandaloneGroups permits identity-only group jobs under the current uid,
	// independently of user-session connector support.
	StandaloneGroups bool
	// tests must explicitly select their uid for isolated system state.
	TestOwnerUID *int
}

type Kind string

const (
	KindPublicURL Kind = "public_url"
	KindService   Kind = "service"
	KindConnector Kind = "connector"
	KindGroup     Kind = "group"
)

type Job struct {
	GroupMember         *controlv1.PublisherGroupMember `json:"group_member,omitempty"`
	GroupInstance       string                          `json:"group_instance,omitempty"`
	IdentityDir         string                          `json:"identity_dir,omitempty"`
	Kind                Kind                            `json:"kind,omitempty"`
	ServiceID           string                          `json:"service_id,omitempty"`
	TrustRevision       int64                           `json:"trust_revision,omitempty"`
	PublisherPool       bool                            `json:"publisher_pool,omitempty"`
	IdentityID          string                          `json:"identity_id,omitempty"`
	StateDir            string                          `json:"state_dir,omitempty"`
	Project             *clientproject.Project          `json:"project,omitempty"`
	ProjectService      string                          `json:"project_service,omitempty"`
	Trust               *targettrust.Snapshot           `json:"trust,omitempty"`
	Endpoint            *controlv1.ServiceEndpoint      `json:"endpoint,omitempty"`
	ID                  string                          `json:"job_id"`
	Name                string                          `json:"name,omitempty"`
	Server              string                          `json:"server"`
	PublisherIdentityID string                          `json:"publisher_identity_id"`
	GrantID             string                          `json:"grant_id"`
	PublicURLID         string                          `json:"public_url_id"`
	Target              string                          `json:"target"`
	Protocol            config.ProtocolName             `json:"protocol"`
	TargetTLSName       string                          `json:"target_tls_name,omitempty"`
	VerifyReadiness     bool                            `json:"verify_readiness,omitempty"`
	ReadinessPath       string                          `json:"readiness_path,omitempty"`
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
	PublicURL        string   `json:"public_url,omitempty"`
	ObservedRevision int64    `json:"observed_revision,omitempty"`
	State            JobState `json:"state"`
	Failure          string   `json:"failure,omitempty"`
	Attempts         uint64   `json:"attempts,omitempty"`
	RunNumber        uint64   `json:"run_number,omitempty"`
}

// JobState is a finite local observation, independent of desired Enabled state.
type JobState string

const (
	JobUnobserved        JobState = ""
	JobStarting          JobState = "starting"
	JobStopping          JobState = "stopping"
	JobStopped           JobState = "stopped"
	JobProvisioning      JobState = "provisioning"
	JobReconciling       JobState = "reconciling"
	JobReady             JobState = "ready"
	JobDraining          JobState = "draining"
	JobRetrying          JobState = "retrying"
	JobBlocked           JobState = "blocked"
	JobTargetUnavailable JobState = "target unavailable"
)

func (s JobState) Valid() bool {
	switch s {
	case JobUnobserved, JobStarting, JobStopping, JobStopped, JobProvisioning, JobReconciling, JobReady, JobDraining, JobRetrying, JobBlocked, JobTargetUnavailable:
		return true
	}
	return false
}

type Registry struct {
	mu       sync.Mutex
	database *clientstate.Database
	root     string
	owner    int
	user     bool
	groups   bool
	pins     map[string]os.FileInfo
	key      []byte
}

// Open uses a standalone database and file wrapping key, including on macOS.
func Open(ctx context.Context, options OpenOptions) (*Registry, error) {
	owner := 0
	if options.User || options.StandaloneGroups {
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
	r := &Registry{database: db, root: db.Root(), owner: owner, user: options.User, groups: options.User || options.StandaloneGroups, pins: map[string]os.FileInfo{}}
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

// Credential exports only an installed job's exact scoped signing identity for
// a private installer handoff. control sessions are outside this representation.
func (r *Registry) Credential(ctx context.Context, job Job) (credentialfile.File, error) {
	identity, private, _, err := r.signingIdentity(ctx, job)
	if err != nil {
		return credentialfile.File{}, err
	}
	return credentialfile.New(job.Server, identity, private)
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
				if existing.Server != job.Server || existing.PublisherIdentityID != job.PublisherIdentityID || existing.GrantID != job.GrantID || existing.PublicURLID != job.PublicURLID || existing.ServiceID != job.ServiceID || existing.Kind != job.Kind {
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
				job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: JobStarting}
				(*jobs)[i] = job
				return nil
			}
			if existing.Server == job.Server && existing.Kind == job.Kind && (job.PublicURLID != "" && existing.PublicURLID == job.PublicURLID || job.ServiceID != "" && existing.ServiceID == job.ServiceID) {
				return ErrJobExists
			}
			// independently supervised jobs need independent runtime identities.
			// one group job may publish many services with its one replica identity.
			if existing.Server == job.Server && existing.PublisherIdentityID == job.PublisherIdentityID {
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
		if err := profile.InstallPublisherIdentity(ctx,
			clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: public, SigningKey: private},
			clientstate.PublisherSelection{Kind: "job", Key: "job:" + job.ID}); err != nil {
			return err
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: JobStarting}
		*jobs = append(*jobs, job)
		return nil
	})
}

// JobKey keeps the resource kind in the key, so a future service ID
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

func ServiceJobKey(server, serviceID string) string {
	return JobKey(server, "service", serviceID)
}

// Remove drops local desired state and its job-scoped signing identity after
// the caller has stopped and joined the worker.
func (r *Registry) Remove(ctx context.Context, id string) error {
	return r.update(ctx, func(jobs *[]Job) error {
		for i, job := range *jobs {
			if job.ID != id {
				continue
			}
			if job.Enabled || job.Status.State != JobStopped {
				return ErrScope
			}
			if job.Kind == KindGroup {
				member, private, profile, err := r.GroupIdentity(ctx, job)
				if err != nil {
					return err
				}
				value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, member, private)
				if err != nil {
					return err
				}
				if err := credentialfile.RetireGroup(ctx, profile, value); err != nil {
					return err
				}
			}
			if job.Kind != KindConnector && job.Kind != KindGroup {
				profile, err := r.database.Server(ctx, job.Server)
				if err != nil {
					return err
				}
				if err := profile.RemovePublisherSelection(ctx, "job", "job:"+id); err != nil {
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
	if identity.TeamId == "" || identity.ClientId != job.PublisherIdentityID || identity.GrantId != job.GrantID || !opaqueid.Valid(identity.KeyId, opaqueid.PublisherIdentityKeyPrefix) {
		return false
	}
	switch job.Kind {
	case KindService:
		return identity.Kind == authorityv1.Service && identity.ServiceId != nil && *identity.ServiceId == job.ServiceID && identity.PublicUrlId == nil && identity.Namespace == nil && identity.DomainId == nil
	case KindPublicURL:
		return identity.Kind == authorityv1.SavedPublicUrl && identity.PublicUrlId != nil && *identity.PublicUrlId == job.PublicURLID && identity.ServiceId == nil && identity.Namespace == nil && identity.DomainId == nil
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
	saved, found, err := profile.SelectedPublisherIdentity(ctx, "job", "job:"+job.ID)
	if err != nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, nil, err
	}
	var identity authorityv1.PublisherEnrollmentResult
	if !found || json.Unmarshal(saved.PublicDocument, &identity) != nil || saved.ID != job.PublisherIdentityID || !matches(job, identity) || len(saved.SigningKey) != ed25519.PrivateKeySize {
		return identity, nil, nil, ErrScope
	}
	return identity, ed25519.PrivateKey(saved.SigningKey), profile, nil
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
			j.Status = Status{State: JobStopping}
			if enabled {
				j.Status.State = JobStarting
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
	if !status.State.Valid() {
		return ErrScope
	}
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
		return r.database.SavePublisherJobRegistry(ctx, value)
	})
}

func (r *Registry) load(ctx context.Context) ([]Job, error) {
	value, found, err := r.database.PublisherJobRegistry(ctx)
	if err != nil || !found {
		return nil, err
	}
	var jobs []Job
	if httpjson.Decode(json.NewDecoder(bytes.NewReader(value)), &jobs) != nil || len(jobs) > 1024 {
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
				if !job.Enabled && job.Status.State == JobStopped {
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
	if !job.Status.State.Valid() {
		return ErrScope
	}
	if job.ReadinessPath != "" && (job.Kind != KindPublicURL || job.Protocol != config.ProtocolHTTP || job.ReadinessPath != "/" && !targetsyntax.ValidMountPrefix(job.ReadinessPath)) {
		return ErrScope
	}
	if !naming.ValidServiceName(job.ID) || len(job.Name) > 128 || strings.TrimSpace(job.Name) != job.Name || strings.ContainsAny(job.Name, "\x00\r\n") || job.Server == "" {
		return ErrScope
	}
	if job.Kind != KindGroup && job.GroupMember != nil ||
		job.Kind != KindGroup && job.GroupInstance != "" ||
		job.Kind != KindGroup && job.IdentityDir != "" ||
		job.Kind != KindConnector && (job.IdentityID != "" || job.StateDir != "") ||
		job.Kind != KindService && job.Kind != KindConnector && job.Endpoint != nil ||
		job.Kind != KindService && (job.Project != nil || job.ProjectService != "" || job.PublisherPool) ||
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
		if job.GroupMember == nil || job.GroupMember.PublisherIdentityId != job.PublisherIdentityID ||
			job.GroupMember.GroupName == "local" || !naming.ValidServiceName(job.GroupMember.GroupName) ||
			!opaqueid.Valid(job.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.GroupMember.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
			job.GroupMember.TeamId == "" || job.GroupMember.GroupId == "" || job.GroupMember.ProjectKey == "" ||
			job.ServiceID != "" || job.PublicURLID != "" || job.Target != "" || job.GrantID != "" || job.Protocol != "" ||
			job.VerifyReadiness ||
			job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 || job.Limits != (publisher.ApplicationLimits{}) {
			return ErrScope
		}
	case KindConnector:
		if !opaqueid.Valid(job.ServiceID, opaqueid.ServicePrefix) || job.PublicURLID != "" || job.PublisherIdentityID != "" || job.GrantID != "" ||
			!opaqueid.Valid(job.IdentityID, opaqueid.IdentityPrefix) || !filepath.IsAbs(job.StateDir) || job.TrustRevision < 1 ||
			job.Limits != (publisher.ApplicationLimits{}) || !job.Protocol.Valid() {
			return ErrScope
		}
	case KindService, KindPublicURL:
		if !opaqueid.Valid(job.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.GrantID, opaqueid.PublisherGrantPrefix) {
			return ErrScope
		}
		if job.Kind == KindService {
			if !opaqueid.Valid(job.ServiceID, opaqueid.ServicePrefix) || job.PublicURLID != "" || job.TrustRevision < 1 || !job.Protocol.Valid() || job.Project == nil && job.ProjectService != "" {
				return ErrScope
			}
		} else if !opaqueid.Valid(job.PublicURLID, opaqueid.PublicURLPrefix) || job.Protocol != config.ProtocolHTTP || job.ServiceID != "" {
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
				if existing.Kind != KindConnector || existing.Server != job.Server || existing.IdentityID != job.IdentityID || existing.ServiceID != job.ServiceID {
					return ErrScope
				}
				job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: JobStarting}
				(*jobs)[i] = job
				return nil
			}
		}
		if len(*jobs) >= 1024 {
			return ErrScope
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: JobStarting}
		*jobs = append(*jobs, job)
		return nil
	})
}
