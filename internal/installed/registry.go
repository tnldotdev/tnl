package installed

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var (
	ErrUnsafeState     = failure.Wrap("open installed job state", failure.ClientStateUnavailable, errors.New("installed job state is unsafe or has changed"))
	ErrLegacyRegistry  = failure.Wrap("open installed job state", failure.InstalledJobRegistryLegacy, errors.New("installed jobs still use the previous ID format"))
	ErrScope           = target.ErrScope
	ErrJobExists       = failure.Wrap("install job", failure.ServerConflict, errors.New("the job binding is already installed"))
	ErrJobNotFound     = failure.Wrap("read installed job", failure.ServerResourceNotFound, errors.New("installed job does not exist"))
	ErrRegistryMissing = errors.New("installed job registry does not exist")
)

type OpenOptions struct {
	Root string
	User bool
	// StandaloneDeployments opens the private fixed-list deployment registry,
	// not the user or system supervisor's public job registry.
	StandaloneDeployments bool
	// tests must explicitly select their uid for isolated system state.
	TestOwnerUID *int
}

type Kind string

const (
	KindService    Kind = "service"
	KindConnector  Kind = "connector"
	KindDeployment Kind = "deployment"
)

type Job struct {
	TelemetryDisabled   bool                                   `json:"telemetry_disabled,omitempty"`
	PreferredRegions    []string                               `json:"preferred_regions,omitempty"`
	DeploymentMember    *controlv1.DeploymentPublisherIdentity `json:"deployment_member,omitempty"`
	DeploymentInstance  string                                 `json:"deployment_instance,omitempty"`
	IdentityDir         string                                 `json:"identity_dir,omitempty"`
	Kind                Kind                                   `json:"kind,omitempty"`
	ServiceID           string                                 `json:"service_id,omitempty"`
	TrustRevision       int64                                  `json:"trust_revision,omitempty"`
	PublisherPool       bool                                   `json:"publisher_pool,omitempty"`
	IdentityID          string                                 `json:"identity_id,omitempty"`
	StateDir            string                                 `json:"state_dir,omitempty"`
	Project             *clientproject.Project                 `json:"project,omitempty"`
	ProjectService      string                                 `json:"project_service,omitempty"`
	Trust               *targettrust.Snapshot                  `json:"trust,omitempty"`
	Endpoint            *controlv1.ServiceEndpoint             `json:"endpoint,omitempty"`
	ID                  string                                 `json:"job_id"`
	Name                string                                 `json:"name,omitempty"`
	Server              string                                 `json:"server"`
	PublisherIdentityID string                                 `json:"publisher_identity_id"`
	GrantID             string                                 `json:"grant_id"`
	Target              string                                 `json:"target"`
	Protocol            config.ProtocolName                    `json:"protocol"`
	ReadinessPath       string                                 `json:"readiness_path,omitempty"`
	// target trust is captured in Trust; control-server roots are independent.
	ServerCAPEM    []byte                   `json:"server_ca_pem,omitempty"`
	StreamCapacity int32                    `json:"stream_capacity,omitempty"`
	Traffic        *trafficlimits.Selection `json:"traffic,omitempty"`
	Enabled        bool                     `json:"enabled"`
	Revision       uint64                   `json:"revision"`
	Status         Status                   `json:"status"`
}

// String keeps private key material out of incidental diagnostic formatting.
func (j Job) String() string {
	type plain Job
	return fmt.Sprintf("%+v", plain(j))
}

func (j Job) GoString() string { return j.String() }

// status contains approved observations only; errors and tokens never enter it.
type Status struct {
	Address          string   `json:"address,omitempty"`
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
	mu               sync.Mutex
	database         *clientstate.Database
	root             string
	owner            int
	user             bool
	fixedDeployments bool
	pins             map[string]os.FileInfo
	key              []byte
}

// Open uses a standalone database and file wrapping key, including on macOS.
func Open(ctx context.Context, options OpenOptions) (*Registry, error) {
	return open(ctx, options, true)
}

// OpenExisting opens the selected supervisor's registry without initializing it
// when no supervisor has been installed.
func OpenExisting(ctx context.Context, options OpenOptions) (*Registry, error) {
	return open(ctx, options, false)
}

func open(ctx context.Context, options OpenOptions, create bool) (*Registry, error) {
	if options.StandaloneDeployments && (options.User || !create) {
		return nil, ErrScope
	}
	owner := 0
	if options.User || options.StandaloneDeployments {
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
	_, dbErr := os.Lstat(clientstate.DatabasePath(root))
	if errors.Is(dbErr, os.ErrNotExist) {
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
	if !create {
		if dbErr != nil {
			if errors.Is(dbErr, os.ErrNotExist) {
				return nil, ErrRegistryMissing
			}
			return nil, ErrUnsafeState
		}
		if info, err := os.Lstat(filepath.Join(root, "jobs.lock")); err != nil || !privateInfo(info, owner, false) {
			return nil, ErrUnsafeState
		}
	}
	db, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return nil, err
	}
	r := &Registry{database: db, root: db.Root(), owner: owner, user: options.User, fixedDeployments: options.StandaloneDeployments, pins: map[string]os.FileInfo{}}
	// pin the registry lock before any reader or writer can use it.
	lock, err := filelock.AcquireContext(ctx, filepath.Join(r.root, "jobs.lock"), owner)
	if err == nil {
		err = r.pin()
		if err == nil {
			_, err = r.load(ctx)
		}
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

// Install returns the saved job with its registry-allocated ID. a failed
// registry write can leave an unused encrypted key, but not a partial job.
func (r *Registry) Install(ctx context.Context, job Job, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (Job, error) {
	if r.fixedDeployments || job.ID != "" || validateJob(&job) != nil {
		return Job{}, ErrScope
	}
	if !matches(job, identity) || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:32]), private) {
		return Job{}, ErrScope
	}
	return r.install(ctx, job, func(existing *Job, job Job) error {
		if existing != nil {
			if existing.PublisherIdentityID != job.PublisherIdentityID || existing.GrantID != job.GrantID {
				return ErrScope
			}
			loaded, key, _, err := r.signingIdentity(ctx, *existing)
			if err != nil {
				return err
			}
			before, _ := json.Marshal(loaded)
			after, _ := json.Marshal(identity)
			if !bytes.Equal(key, private) || !bytes.Equal(before, after) {
				return ErrScope
			}
			// a reinstall may refresh local settings, not the signing authority.
			return nil
		}
		profile, err := r.database.Server(ctx, job.Server)
		if err != nil {
			return err
		}
		public, err := json.Marshal(identity)
		if err != nil {
			return err
		}
		return profile.InstallPublisherIdentity(ctx,
			clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: public, SigningKey: private},
			clientstate.PublisherSelection{Kind: "job", Key: "job:" + job.ID})
	})
}

// jobBinding identifies the slot occupied by a definition, not its credentials.
// a matching slot can be reused only after verifying the exact authority.
type jobBinding struct {
	kind                          Kind
	server, resourceID, qualifier string
}

func (job Job) binding() jobBinding {
	switch job.Kind {
	case KindConnector:
		return jobBinding{job.Kind, job.Server, job.ServiceID, job.IdentityID}
	case KindDeployment:
		return jobBinding{job.Kind, job.Server, job.DeploymentMember.DeploymentId, job.DeploymentInstance}
	default:
		return jobBinding{job.Kind, job.Server, job.ServiceID, ""}
	}
}

type publisherBinding struct{ server, id string }

func (job Job) publisherBinding() publisherBinding {
	return publisherBinding{job.Server, job.PublisherIdentityID}
}

func (r *Registry) install(ctx context.Context, job Job, retain func(existing *Job, job Job) error) (Job, error) {
	err := r.update(ctx, func(jobs *[]Job) error {
		for i, existing := range *jobs {
			if existing.binding() != job.binding() {
				// independently supervised jobs need independent publisher identities.
				if job.PublisherIdentityID != "" && existing.publisherBinding() == job.publisherBinding() {
					return ErrJobExists
				}
				continue
			}
			job = restartDefinition(job, existing.ID, existing.Revision+1)
			if err := retain(&existing, job); err != nil {
				return err
			}
			(*jobs)[i] = job
			return nil
		}
		id, err := newJobID(*jobs)
		if err != nil {
			return err
		}
		job = restartDefinition(job, id, 1)
		if err := retain(nil, job); err != nil {
			return err
		}
		*jobs = append(*jobs, job)
		return nil
	})
	if err != nil {
		return Job{}, err
	}
	return job, nil
}

func newJobID(jobs []Job) (string, error) {
	for {
		id, err := opaqueid.New(opaqueid.JobPrefix)
		if err != nil {
			return "", err
		}
		if !slices.ContainsFunc(jobs, func(job Job) bool { return job.ID == id }) {
			return id, nil
		}
	}
}

func restartDefinition(job Job, id string, revision uint64) Job {
	job.ID, job.Enabled, job.Revision, job.Status = id, true, revision, Status{State: JobStarting}
	return job
}

// Remove drops local desired state and its job-scoped signing identity or
// connector port assignment after the caller has stopped and joined the worker.
func (r *Registry) Remove(ctx context.Context, id string) error {
	return r.update(ctx, func(jobs *[]Job) error {
		for i, job := range *jobs {
			if job.ID != id {
				continue
			}
			if job.Enabled || job.Status.State != JobStopped {
				return ErrScope
			}
			if job.Kind == KindConnector {
				if err := releaseConnectorPort(ctx, job); err != nil {
					return err
				}
			}
			if job.Kind == KindDeployment {
				member, private, profile, err := r.DeploymentIdentity(ctx, job)
				if err != nil {
					return err
				}
				value, err := credentialfile.NewDeployment(job.Server, job.DeploymentInstance, member, private)
				if err != nil {
					return err
				}
				if err := credentialfile.RetireDeployment(ctx, profile, value); err != nil {
					return err
				}
			}
			if job.Kind != KindConnector && job.Kind != KindDeployment {
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
		return identity.Kind == authorityv1.Service && identity.ServiceId != nil && *identity.ServiceId == job.ServiceID && identity.Namespace == nil && identity.DomainId == nil
	default:
		return false
	}
}

func (r *Registry) signingIdentity(ctx context.Context, job Job) (authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, *clientstate.Store, error) {
	if !opaqueid.Valid(job.ID, opaqueid.JobPrefix) {
		return authorityv1.PublisherEnrollmentResult{}, nil, nil, ErrScope
	}
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

// ResolveJob selects only an exact public job ID in this registry.
func (r *Registry) ResolveJob(ctx context.Context, selected string) (Job, error) {
	if !opaqueid.Valid(selected, opaqueid.JobPrefix) {
		return Job{}, ErrJobNotFound
	}
	jobs, err := r.List(ctx)
	if err != nil {
		return Job{}, err
	}
	for _, job := range jobs {
		if selected == job.ID {
			return job, nil
		}
	}
	return Job{}, ErrJobNotFound
}

func (r *Registry) status(ctx context.Context, id string, revision uint64, status Status) error {
	_, err := r.updateStatus(ctx, id, revision, status)
	return err
}

func (r *Registry) updateStatus(ctx context.Context, id string, revision uint64, status Status) (bool, error) {
	if !status.State.Valid() {
		return false, ErrScope
	}
	applied := false
	err := r.update(ctx, func(jobs *[]Job) error {
		for i := range *jobs {
			if (*jobs)[i].ID == id && (*jobs)[i].Revision == revision {
				(*jobs)[i].Status = status
				applied = true
				return nil
			}
		}
		return nil // an observation from replaced work must not overwrite new state.
	})
	return applied, err
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
	if httpjson.Decode(json.NewDecoder(bytes.NewReader(value)), &jobs) != nil {
		return nil, ErrUnsafeState
	}
	seen := map[string]bool{}
	bindings := map[jobBinding]bool{}
	publishers := map[publisherBinding]bool{}
	for i := range jobs {
		original := jobs[i]
		if !r.fixedDeployments && !opaqueid.Valid(original.ID, opaqueid.JobPrefix) {
			if naming.ValidServiceName(original.ID) {
				return nil, ErrLegacyRegistry
			}
			return nil, ErrUnsafeState
		}
		if validateJob(&jobs[i]) != nil || jobs[i].Server != original.Server || jobs[i].Target != original.Target || original.Revision == 0 || seen[original.ID] {
			return nil, ErrUnsafeState
		}
		if r.fixedDeployments && (original.Kind != KindDeployment || original.ID != fixedDeploymentID(jobs[i])) {
			return nil, ErrUnsafeState
		}
		binding := jobs[i].binding()
		if bindings[binding] {
			return nil, ErrUnsafeState
		}
		if publisher := jobs[i].publisherBinding(); publisher.id != "" {
			if publishers[publisher] {
				return nil, ErrUnsafeState
			}
			publishers[publisher] = true
		}
		seen[original.ID] = true
		bindings[binding] = true
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

// validateJob checks and normalizes definition fields. the caller verifies whether
// the public ID must be absent (installation) or present (loading saved state).
func validateJob(job *Job) error {
	preferences, err := region.Preferences(job.PreferredRegions)
	if err != nil || len(preferences) != 0 && job.Kind != KindService {
		return ErrScope
	}
	job.PreferredRegions = preferences
	if !job.Status.State.Valid() {
		return ErrScope
	}
	if job.ReadinessPath != "" && (job.Kind != KindService || job.Protocol != config.ProtocolHTTP || job.ReadinessPath != "/" && !targetsyntax.ValidMountPrefix(job.ReadinessPath)) {
		return ErrScope
	}
	if len(job.Name) > 128 || strings.TrimSpace(job.Name) != job.Name || strings.ContainsAny(job.Name, "\x00\r\n") || job.Server == "" {
		return ErrScope
	}
	if job.Kind != KindDeployment && job.DeploymentMember != nil ||
		job.Kind != KindDeployment && job.DeploymentInstance != "" ||
		job.Kind != KindDeployment && job.IdentityDir != "" ||
		job.Kind != KindConnector && (job.IdentityID != "" || job.StateDir != "") ||
		job.Kind != KindService && job.Kind != KindConnector && job.Endpoint != nil ||
		job.Kind != KindService && (job.Project != nil || job.ProjectService != "" || job.PublisherPool) ||
		job.Kind == KindDeployment && (job.Trust != nil || job.TrustRevision != 0) ||
		job.Kind != KindService && (job.StreamCapacity != 0 || job.Traffic != nil) {
		return ErrScope
	}
	switch job.Kind {
	case KindDeployment:
		if !naming.ValidServiceName(job.DeploymentInstance) {
			return ErrScope
		}
		if job.IdentityDir != "" && (!filepath.IsAbs(job.IdentityDir) || filepath.Clean(job.IdentityDir) != job.IdentityDir) {
			return ErrScope
		}
		if job.DeploymentMember == nil || job.DeploymentMember.PublisherIdentityId != job.PublisherIdentityID ||
			job.DeploymentMember.DeploymentName == "local" || !naming.ValidServiceName(job.DeploymentMember.DeploymentName) ||
			!opaqueid.Valid(job.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.DeploymentMember.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
			job.DeploymentMember.TeamId == "" || !opaqueid.Valid(job.DeploymentMember.DeploymentId, "dpl_") || job.DeploymentMember.ProjectKey == "" ||
			job.ServiceID != "" || job.Target != "" || job.GrantID != "" || job.Protocol != "" {
			return ErrScope
		}
	case KindConnector:
		if !opaqueid.Valid(job.ServiceID, opaqueid.ServicePrefix) || job.PublisherIdentityID != "" || job.GrantID != "" ||
			!opaqueid.Valid(job.IdentityID, opaqueid.IdentityPrefix) || !filepath.IsAbs(job.StateDir) || filepath.Clean(job.StateDir) != job.StateDir || job.TrustRevision < 1 ||
			!job.Protocol.Valid() {
			return ErrScope
		}
	case KindService:
		if !opaqueid.Valid(job.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(job.GrantID, opaqueid.PublisherGrantPrefix) {
			return ErrScope
		}
		if !opaqueid.Valid(job.ServiceID, opaqueid.ServicePrefix) || job.TrustRevision < 1 || !job.Protocol.Valid() || job.Project == nil && job.ProjectService != "" ||
			job.StreamCapacity < 0 || job.StreamCapacity > 4096 {
			return ErrScope
		}
		if job.Traffic != nil {
			if err := job.Traffic.Validate(); err != nil {
				return ErrScope
			}
			job.Traffic = job.Traffic.Clone()
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
	if job.Kind == KindDeployment {
		return nil
	}
	return validateTarget(job)
}

// InstallConnector stores user desired state only. credentials remain in the
// signed-in profile, and the worker checks the exact identity at every start.
func (r *Registry) InstallConnector(ctx context.Context, job Job) (Job, error) {
	if !r.user || job.Kind != KindConnector || job.ID != "" {
		return Job{}, ErrScope
	}
	if err := validateJob(&job); err != nil {
		return Job{}, err
	}
	return r.install(ctx, job, func(existing *Job, job Job) error {
		if existing != nil && existing.StateDir != job.StateDir {
			return ErrScope
		}
		return nil
	})
}

// FindConnector finds the exact saved definition before selecting a listener.
func (r *Registry) FindConnector(ctx context.Context, server, serviceID, identityID, stateDir string) (Job, bool, error) {
	server, err := clientstate.CanonicalServer(server)
	if err != nil || !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || !opaqueid.Valid(identityID, opaqueid.IdentityPrefix) || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return Job{}, false, ErrScope
	}
	binding := Job{Kind: KindConnector, Server: server, ServiceID: serviceID, IdentityID: identityID}.binding()
	jobs, err := r.List(ctx)
	if err != nil {
		return Job{}, false, err
	}
	for _, job := range jobs {
		if job.binding() == binding {
			if job.StateDir != stateDir {
				return Job{}, false, ErrScope
			}
			return job, true, nil
		}
	}
	return Job{}, false, nil
}
