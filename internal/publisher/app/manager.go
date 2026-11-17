package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
)

const LeaseDuration = 20 * time.Second
const CleanupGrace = 10 * time.Second

const stoppedOutcomeLifetime = 2 * time.Minute
const maxStoppedOutcomes = 64

// permanent cleanup failures cannot be repaired with the captured resources.
// registration stopped is returned only after the worker joins and its local
// registration is released; neither marker claims remote cleanup succeeded.
var ErrCleanupPermanent = errors.New("publication cleanup cannot be retried")
var ErrRegistrationStopped = errors.New("publication stopped with a cleanup failure")

type Run func(context.Context, Service, func(PublicationUpdate) error) error

type registration struct {
	owner   string
	pid     int
	expires time.Time
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	// an unbound preparation can be released with the application's target.
	// retain that exact cleanup request without claiming a bound listener.
	cleanupTarget  *string
	shutdownUntil  time.Time
	shutdown       context.Context
	stopShutdown   context.CancelCauseFunc
	shutdownTimer  *time.Timer
	shutdownDone   chan struct{}
	cleanupPending bool
	cleanup        *cleanupAttempt
	cleanupFailure error
	retryUntil     time.Time
}

// stopped outcomes contain no worker, key, or cleanup callback. they only let an
// exact unregister retry recover a lost reply while this owner exists.
type stoppedOutcome struct {
	service, owner, target string
	expires                time.Time
	err                    error
}

type Manager struct {
	op            sync.Mutex
	mu            sync.Mutex
	ctx           context.Context
	database      *clientstate.Database
	snapshot      Snapshot
	registrations map[string]*registration
	run           Run
	Alive         func(int) bool
	// cleanup runs only after the worker joins. a failure retains the
	// registration and its exact resources for a later unregister attempt unless
	// the resource owner marks the failure as permanent. callbacks borrow their
	// bounded operation context through PublicationCleanupContext.
	Cleanup func(Service) error
	// the process owner supplies one deadline for all registrations on exit.
	ShutdownDeadline func() time.Time
	idleSince        time.Time
	preparing        int
	closed           bool
	closeOnce        sync.Once
	writeErr         error
	retirementErr    error
	stopped          map[string]stoppedOutcome
	targetChanges    map[string]chan struct{}
}

func New(ctx context.Context, project string, database *clientstate.Database, services []Service, run Run) (*Manager, error) {
	if database == nil {
		return nil, errors.New("clientruntime: open client state is required")
	}
	previous, err := ReadSnapshotFrom(ctx, database, project)
	if err != nil {
		return nil, err
	}
	m := &Manager{ctx: ctx, database: database, run: run, registrations: map[string]*registration{}, idleSince: time.Now(), snapshot: previous,
		ShutdownDeadline: sync.OnceValue(func() time.Time { return time.Now().Add(10 * time.Second) })}
	m.snapshot.Services = slices.Clone(services)
	slices.SortFunc(m.snapshot.Services, func(a, b Service) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	for index := range m.snapshot.Services {
		for _, old := range previous.Services {
			if old.Name == m.snapshot.Services[index].Name {
				m.snapshot.Services[index].Failure = old.Failure
				m.snapshot.Services[index].PublicURL = old.PublicURL
			}
		}
	}
	kind := "runtime.started"
	for _, old := range previous.Services {
		if old.Registered {
			kind = "runtime.restarted"
			if service := m.serviceLocked(old.Name); service != nil {
				service.Failure = "runtime.manager_restarted"
			}
		}
	}
	m.emitLocked(kind, nil)
	return m, m.writeErr
}

func (m *Manager) emitLocked(kind string, service *Service) {
	base := context.WithoutCancel(m.ctx)
	until := time.Now().Add(5 * time.Second)
	if (m.closed || m.ctx.Err() != nil) && m.ShutdownDeadline != nil {
		if parent := m.ShutdownDeadline(); parent.Before(until) {
			until = parent
		}
	}
	if service != nil {
		if reg := m.registrations[service.Name]; reg != nil {
			if reg.cleanup != nil {
				base = reg.cleanup.ctx
			} else {
				if !reg.shutdownUntil.IsZero() && reg.shutdownUntil.Before(until) {
					until = reg.shutdownUntil
				}
				if reg.shutdown != nil {
					base = reg.shutdown
				}
			}
		}
	}
	ctx, cancel := context.WithDeadline(base, until)
	defer cancel()
	if err := CommitSnapshot(ctx, m.database, &m.snapshot, kind, service); err != nil {
		m.writeErr = err
	}
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	copy := m.snapshot
	copy.Services = slices.Clone(copy.Services)
	for index := range copy.Services {
		if value := copy.Services[index].Observation; value != nil {
			observation := *value
			copy.Services[index].Observation = &observation
		}
	}
	project := m.snapshot.Project
	m.mu.Unlock()
	// retain the journal's services and cursor together. publication writers share
	// the journal and do not take the manager lock; reading it must not block leases.
	if latest, err := ReadSnapshotFrom(context.Background(), m.database, project); err == nil {
		copy = latest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for index := range copy.Services {
		service := &copy.Services[index]
		reg := m.registrations[service.Name]
		current := m.serviceLocked(service.Name)
		if service.Registered && (m.closed || reg == nil || current == nil || current.RegistrationID != service.RegistrationID || !current.Registered || time.Now().After(reg.expires) || m.Alive != nil && !m.Alive(reg.pid)) {
			service.invalidateRegistration()
			service.Failure = "runtime.registration_stale"
		}
	}
	return copy
}

func (m *Manager) BeginPreparation() func() {
	m.mu.Lock()
	m.preparing++
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.preparing--
		if m.preparing == 0 && len(m.registrations) == 0 {
			m.idleSince = time.Now()
		}
	}
}

// configure reconciles configured names without changing a live listener's
// publication. removed services stop their publishers before leaving the model.
func (m *Manager) Configure(services []Service) error {
	m.op.Lock()
	defer m.op.Unlock()
	wanted := map[string]bool{}
	definitions := map[string]Service{}
	for _, service := range services {
		wanted[service.Name] = true
		definitions[service.Name] = service
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrRegistrationStale
	}
	type removal struct{ id, owner string }
	var removed []removal
	for name, reg := range m.registrations {
		if !wanted[name] || definitions[name].ServiceProtocol != m.serviceLocked(name).ServiceProtocol {
			removed = append(removed, removal{m.serviceLocked(name).RegistrationID, reg.owner})
		}
	}
	m.mu.Unlock()
	for _, entry := range removed {
		if err := m.unregister(entry.id, entry.owner, false); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := slices.Clone(services)
	slices.SortFunc(next, func(a, b Service) int { return strings.Compare(a.Name, b.Name) })
	changed := len(next) != len(m.snapshot.Services)
	for index, configured := range next {
		if previous := m.serviceLocked(configured.Name); previous != nil {
			if previous.Directory != configured.Directory || previous.Readiness != configured.Readiness || previous.ServiceProtocol != configured.ServiceProtocol {
				changed = true
			}
			next[index] = *previous
			next[index].Directory, next[index].Readiness, next[index].ServiceProtocol = configured.Directory, configured.Readiness, configured.ServiceProtocol
			if previous.Readiness != configured.Readiness {
				next[index].invalidateReadiness()
			}
		} else {
			changed = true
		}
	}
	if changed {
		m.snapshot.Services = next
		m.emitLocked("runtime.configured", nil)
	}
	return m.writeErr
}

func (m *Manager) serviceLocked(name string) *Service {
	for index := range m.snapshot.Services {
		if m.snapshot.Services[index].Name == name {
			return &m.snapshot.Services[index]
		}
	}
	return nil
}

func (m *Manager) Reserve(name, owner string, pid int, publicURL string) (string, error) {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return "", ErrRegistrationStale
	}
	if owner == "" || pid <= 0 || m.Alive != nil && !m.Alive(pid) {
		return "", ErrRegistrationStale
	}
	service := m.serviceLocked(name)
	if service == nil {
		return "", errors.New("service is not configured")
	}
	if current := m.registrations[name]; current != nil {
		if time.Now().After(current.expires) || m.Alive != nil && !m.Alive(current.pid) {
			id, previousOwner := service.RegistrationID, current.owner
			m.mu.Unlock()
			err := m.unregister(id, previousOwner, false)
			m.mu.Lock()
			if err != nil {
				return "", err
			}
		} else {
			if current.owner != owner || current.pid != pid {
				return "", ErrOwnerConflict
			}
			current.expires = time.Now().Add(LeaseDuration)
			return service.RegistrationID, nil
		}
	}
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	service.reserve(reservedRegistration{id: "reg_" + hex.EncodeToString(bytes), publicURL: publicURL})
	// a replacement registration invalidates the previous binding's outcomes.
	for id, outcome := range m.stopped {
		if outcome.service == name {
			delete(m.stopped, id)
		}
	}
	m.registrations[name] = &registration{owner: owner, pid: pid, expires: time.Now().Add(LeaseDuration)}
	m.idleSince = time.Time{}
	m.emitLocked("service.prepared", service)
	return service.RegistrationID, m.writeErr
}

func (m *Manager) findLocked(id, owner string) (*Service, *registration) {
	if m.closed {
		return nil, nil
	}
	for index := range m.snapshot.Services {
		service := &m.snapshot.Services[index]
		if service.RegistrationID == id {
			if reg := m.registrations[service.Name]; reg != nil && !reg.cleanupPending && reg.owner == owner && time.Now().Before(reg.expires) && (m.Alive == nil || m.Alive(reg.pid)) {
				return service, reg
			}
		}
	}
	return nil, nil
}

func (m *Manager) Renew(id, owner string) error {
	return m.renew(id, owner, "", false)
}

func (m *Manager) RenewTarget(id, owner, target string) error {
	return m.renew(id, owner, target, true)
}

func (m *Manager) renew(id, owner, target string, fenced bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	service, reg := m.findLocked(id, owner)
	if reg == nil {
		return ErrRegistrationStale
	}
	if fenced && service.Registered && service.Target != target {
		return ErrRegistrationStale
	}
	reg.expires = time.Now().Add(LeaseDuration)
	return m.writeErr
}

// register acknowledges ownership and a bound target. provisioning happens in
// the worker after this method returns and has its own observations.
func (m *Manager) Register(id, owner, target, framework string) error {
	return m.RegisterContext(m.ctx, id, owner, target, framework)
}

func (m *Manager) RegisterContext(scheduling context.Context, id, owner, target, framework string) error {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	service, reg := m.findLocked(id, owner)
	if reg == nil {
		m.mu.Unlock()
		return ErrRegistrationStale
	}
	var targetErr error
	if service.ServiceProtocol == "" || service.ServiceProtocol == "http" {
		_, targetErr = targetsyntax.ParseCanonicalTarget(target)
	} else {
		var canonical string
		canonical, targetErr = tcptarget.Normalize(target)
		if canonical != target {
			targetErr = errors.New("target must be canonical")
		}
	}
	if targetErr != nil {
		m.mu.Unlock()
		return targetErr
	}
	if m.run == nil {
		m.mu.Unlock()
		return errors.New("clientruntime: worker is required")
	}
	if service.Registered && service.Target == target && reg.cancel != nil {
		reg.expires = time.Now().Add(LeaseDuration)
		m.mu.Unlock()
		return nil
	}
	if reg.cancel != nil {
		m.shutdownLocked(reg)
		service.invalidateRegistration()
		m.emitLocked("service.replacing", service)
		reg.cancel()
		done := reg.done
		m.mu.Unlock()
		<-done
		m.mu.Lock()
	}
	if reg.err != nil {
		m.retirementErr = errors.Join(m.retirementErr, reg.err)
		// joining proves the old worker stopped, not that its cleanup succeeded.
		// retain its exact stopped capability for unregister rather than clearing
		// the failure and starting another publisher over unconfirmed resources.
		if !service.Registered || service.Target != target {
			service.Failure = "runtime.publication_cleanup_failed"
			m.emitLocked("service.failed", service)
			m.retirementErr = errors.Join(m.retirementErr, m.writeErr)
			err := errors.Join(reg.err, m.writeErr)
			m.mu.Unlock()
			return err
		}
		// a failed publication can retry its still-registered listener without
		// replacing app ownership. retain that previous failure in retirement.
	}
	if err := service.bindListener(boundListener{target: target, framework: framework}); err != nil {
		m.mu.Unlock()
		return err
	}
	reg.expires = time.Now().Add(LeaseDuration)
	if !reg.shutdownUntil.IsZero() {
		reg.finishShutdown()
	}
	reg.shutdownUntil = time.Time{}
	ctx, cancel := context.WithCancel(observability.LinkContext(m.ctx, scheduling))
	reg.cancel, reg.done = cancel, make(chan struct{})
	reg.err = nil
	copy, done := *service, reg.done
	m.emitLocked("service.registered", service)
	if err := m.writeErr; err != nil {
		cancel()
		close(done)
		reg.cancel = nil
		service.invalidateRegistration()
		m.mu.Unlock()
		return err
	}
	observability.ClientLifecycle(m.ctx, observability.EventRegistered)
	m.mu.Unlock()
	go func() {
		defer close(done)
		err := m.run(ctx, copy, func(update PublicationUpdate) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			current, active := m.findLocked(id, owner)
			if active == nil || active.done != done || current.Target != copy.Target || ctx.Err() != nil {
				return ErrRegistrationStale
			}
			return m.publishedLocked(id, update)
		})
		m.mu.Lock()
		defer m.mu.Unlock()
		current := m.serviceLocked(copy.Name)
		if current == nil || current.RegistrationID != id || reg.done != done {
			return
		}
		current.endPublication()
		reg.cancel = nil
		reg.err = independentWorkerFailure(err, ctx.Err() != nil)
		if err != nil && ctx.Err() == nil {
			current.Failure = "runtime.publication_failed"
			if reason, _, ok := failure.Describe(err); ok {
				current.Failure = string(reason)
			}
			m.emitLocked("service.failed", current)
		} else if ctx.Err() == nil {
			m.emitLocked("service.stopped", current)
		}
	}()
	return nil
}

func (m *Manager) Published(id string, update PublicationUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publishedLocked(id, update)
}

func (m *Manager) publishedLocked(id string, update PublicationUpdate) error {
	if m.closed {
		return ErrRegistrationStale
	}
	for index := range m.snapshot.Services {
		service := &m.snapshot.Services[index]
		reg := m.registrations[service.Name]
		if service.RegistrationID != id || !service.Registered || reg == nil || time.Now().After(reg.expires) {
			continue
		}
		if m.Alive != nil && !m.Alive(reg.pid) {
			return ErrRegistrationStale
		}
		becameRoutable, err := service.publish(update)
		if err != nil {
			return err
		}
		m.emitLocked("service.publication", service)
		if becameRoutable && m.writeErr == nil {
			observability.ClientLifecycle(m.ctx, observability.EventPublicationReady)
		}
		return m.writeErr
	}
	return ErrRegistrationStale
}

// CurrentRegistration checks listener ownership before a publish run exists.
func (m *Manager) CurrentRegistration(name, id, target string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentRegistrationLocked(name, id, target)
}

func (m *Manager) currentRegistrationLocked(name, id, target string) bool {
	service := m.serviceLocked(name)
	reg := m.registrations[name]
	return !m.closed && service != nil && reg != nil && time.Now().Before(reg.expires) && (m.Alive == nil || m.Alive(reg.pid)) && service.Registered && service.RegistrationID == id && service.Target == target
}

// CurrentRun requires an exact, nonzero run. routability and readiness are
// separate observations and are not required during provisioning or drain.
func (m *Manager) CurrentRun(name, id, target string, run uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentRunLocked(name, id, target, run)
}

func (m *Manager) currentRunLocked(name, id, target string, run uint64) bool {
	return run != 0 && m.currentRegistrationLocked(name, id, target) && m.serviceLocked(name).RunNumber == run
}

// ServiceForRun reads the live registration and run together, without combining
// a journal snapshot with a later ownership check.
func (m *Manager) ServiceForRun(name, id, target string, run uint64) (Service, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.currentRunLocked(name, id, target, run) {
		return Service{}, false
	}
	service := *m.serviceLocked(name)
	if service.Observation != nil {
		observation := *service.Observation
		service.Observation = &observation
	}
	return service, true
}

func (m *Manager) BindTunnel(name, id, target, tunnelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	service := m.serviceLocked(name)
	if m.closed || service == nil || service.RegistrationID != id || service.Target != target || !service.Registered {
		return ErrRegistrationStale
	}
	service.TunnelID = tunnelID
	m.emitLocked("service.bound", service)
	return m.writeErr
}

func (m *Manager) RecordFailure(name, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if service := m.serviceLocked(name); service != nil && !service.Registered {
		service.Failure = reason
		m.emitLocked("service.failed", service)
	}
}

// RecordWarning retains an authored reason while a registered publisher retries.
// repeated transport errors do not advance the event cursor without a change.
func (m *Manager) RecordWarning(name, registrationID, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if service := m.serviceLocked(name); service != nil && service.Registered && service.RegistrationID == registrationID && service.Failure != reason {
		service.Failure = reason
		m.emitLocked("service.warning", service)
	}
}

func (m *Manager) SetProvisioningStage(name, registrationID string, run uint64, stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	service := m.serviceLocked(name)
	if service == nil || !service.Registered || service.Routable || service.RegistrationID != registrationID || service.RunNumber != run || service.ProvisioningStage == stage {
		return
	}
	service.ProvisioningStage = stage
	m.emitLocked("service.provisioning", service)
}

func (m *Manager) Observe(observation Observation) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	for index := range m.snapshot.Services {
		service := &m.snapshot.Services[index]
		if service.RegistrationID != observation.RegistrationID {
			continue
		}
		reg := m.registrations[service.Name]
		if reg == nil || time.Now().After(reg.expires) || m.Alive != nil && !m.Alive(reg.pid) {
			return false
		}
		if !service.acceptObservation(observation) {
			return false
		}
		m.emitLocked("service.readiness", service)
		return true
	}
	return false
}

// AddService adds one invocation to the same worker and journal boundary. it
// cannot replace a configured service or an existing invocation definition.
func (m *Manager) AddService(service Service) error {
	if !opaqueid.Valid(service.Name, opaqueid.InvocationPrefix) {
		return errors.New("invocation service ID is required")
	}
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrRegistrationStale
	}
	if current := m.serviceLocked(service.Name); current != nil {
		if current.RegistrationID != "" || current.Registered {
			return ErrOwnerConflict
		}
		*current = service
		m.emitLocked("service.configured", nil)
		return m.writeErr
	}
	m.snapshot.Services = append(m.snapshot.Services, service)
	slices.SortFunc(m.snapshot.Services, func(a, b Service) int { return strings.Compare(a.Name, b.Name) })
	m.emitLocked("service.configured", nil)
	return m.writeErr
}

func (m *Manager) ServiceForRegistration(id string) (Service, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, service := range m.snapshot.Services {
		if service.RegistrationID == id {
			return service, true
		}
	}
	return Service{}, false
}

func (m *Manager) Unregister(id, owner string) error {
	m.op.Lock()
	defer m.op.Unlock()
	return m.unregister(id, owner, false)
}

func (m *Manager) UnregisterTarget(id, owner, target string) error {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	if outcome, found := m.stoppedOutcomeLocked(id, owner, target); found {
		m.mu.Unlock()
		return outcome.err
	}
	service, reg := m.findUnregisterLocked(id, owner)
	if reg == nil || service.Target != "" && service.Target != target ||
		reg.cleanupTarget != nil && *reg.cleanupTarget != target {
		m.mu.Unlock()
		return ErrRegistrationStale
	}
	if reg.cleanupTarget == nil {
		reg.cleanupTarget = &target
	}
	m.mu.Unlock()
	return m.unregister(id, owner, true)
}

// a stopped allocation retains its exact cleanup capability after SDK lease
// expiry. this does not make the registration renewable or publication current.
func (m *Manager) findUnregisterLocked(id, owner string) (*Service, *registration) {
	if !m.closed {
		for name, reg := range m.registrations {
			if service := m.serviceLocked(name); service != nil && service.RegistrationID == id && reg.owner == owner && reg.cleanupPending {
				return service, reg
			}
		}
	}
	return m.findLocked(id, owner)
}

func (m *Manager) unregister(id, owner string, explicit bool) (result error) {
	m.mu.Lock()
	var service *Service
	var reg *registration
	for index := range m.snapshot.Services {
		candidate := &m.snapshot.Services[index]
		if candidate.RegistrationID == id {
			if current := m.registrations[candidate.Name]; current != nil && current.owner == owner {
				service, reg = candidate, current
			}
			break
		}
	}
	if reg == nil {
		m.mu.Unlock()
		return ErrRegistrationStale
	}
	retry := reg.cleanupPending
	if retry && (!explicit || m.closed || m.ctx.Err() != nil) && !time.Now().Before(reg.shutdownUntil) {
		// automatic cleanup exhausted its one budget. retain the exact failure
		// and allocation without appending another identical failure per sweep.
		err := reg.cleanupFailure
		m.mu.Unlock()
		return err
	}
	if !retry {
		m.shutdownLocked(reg)
		service.invalidateRegistration()
		service.endPublication()
		m.emitLocked("service.unregistered", service)
		if reg.cancel != nil {
			reg.cancel()
		}
	}
	done := reg.done
	stopped := *service
	m.mu.Unlock()
	if done != nil {
		<-done
	}
	m.mu.Lock()
	runErr := reg.err
	if !retry && !time.Now().Before(reg.shutdownUntil) {
		reg.stopShutdown(context.DeadlineExceeded)
	}
	if cause := context.Cause(reg.shutdown); !retry && errors.Is(cause, context.DeadlineExceeded) {
		runErr = errors.Join(runErr, cause)
	}
	reg.err = nil
	m.retirementErr = errors.Join(m.retirementErr, runErr)
	base, until := reg.shutdown, reg.shutdownUntil
	detached := retry && explicit && !m.closed && m.ctx.Err() == nil
	if detached {
		// an explicit retry joins a new cleanup operation, not another turn of
		// the automatic shutdown loop. never change the original worker fence.
		base, until = context.WithoutCancel(m.ctx), time.Now().Add(10*time.Second)
		if !reg.retryUntil.IsZero() && reg.retryUntil.Before(until) {
			until = reg.retryUntil
		}
		reg.retryUntil = time.Time{}
	}
	cleanup := m.beginCleanupLocked(reg, base, until, detached)
	m.mu.Unlock()
	defer func() {
		if cause := m.finishCleanup(reg, cleanup); cause != nil {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.retirementErr = errors.Join(m.retirementErr, cause)
			result = errors.Join(result, cause)
			if outcome, stopped := m.stopped[id]; stopped {
				if !errors.Is(result, ErrRegistrationStopped) {
					result = errors.Join(ErrRegistrationStopped, result)
				}
				outcome.err = result
				m.stopped[id] = outcome
			}
		}
	}()
	var cleanupErr error
	if m.Cleanup != nil {
		cleanupErr = errors.Join(m.Cleanup(stopped), context.Cause(cleanup.ctx))
		if cleanupErr != nil && !errors.Is(cleanupErr, ErrCleanupPermanent) {
			m.mu.Lock()
			reg.cleanupPending = true
			reg.cleanupFailure = errors.Join(runErr, cleanupErr)
			m.retirementErr = errors.Join(m.retirementErr, cleanupErr)
			m.mu.Unlock()
			return errors.Join(runErr, cleanupErr)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	service.releaseRegistration()
	if cleanupErr != nil {
		service.Failure = "runtime.publication_cleanup_failed"
	}
	m.emitLocked("service.stopped", service)
	reg.finishShutdown()
	delete(m.registrations, service.Name)
	if len(m.registrations) == 0 {
		m.idleSince = time.Now()
	}
	m.retirementErr = errors.Join(m.retirementErr, cleanupErr, m.writeErr)
	result = errors.Join(runErr, cleanupErr, m.writeErr)
	if result != nil {
		result = errors.Join(ErrRegistrationStopped, result)
	}
	target := stopped.Target
	if reg.cleanupTarget != nil {
		target = *reg.cleanupTarget
	}
	m.rememberStoppedLocked(stopped, owner, target, result)
	return result
}

// ServiceForUnregister preserves the capability's service fence for exact lost
// reply recovery without making a stopped registration current again.
func (m *Manager) ServiceForUnregister(id, owner, target string) (Service, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, service := range m.snapshot.Services {
		if service.RegistrationID == id {
			return service, true
		}
	}
	if outcome, found := m.stoppedOutcomeLocked(id, owner, target); found {
		return Service{Name: outcome.service}, true
	}
	return Service{}, false
}

func (m *Manager) stoppedOutcomeLocked(id, owner, target string) (stoppedOutcome, bool) {
	m.pruneStoppedLocked(time.Now())
	outcome, found := m.stopped[id]
	if !found || outcome.owner != owner || outcome.target != target {
		return stoppedOutcome{}, false
	}
	service := m.serviceLocked(outcome.service)
	if service == nil || service.RegistrationID != "" {
		return stoppedOutcome{}, false
	}
	return outcome, true
}

func (m *Manager) pruneStoppedLocked(now time.Time) {
	for id, outcome := range m.stopped {
		if !now.Before(outcome.expires) {
			delete(m.stopped, id)
		}
	}
}

func (m *Manager) rememberStoppedLocked(service Service, owner, target string, err error) {
	now := time.Now()
	m.pruneStoppedLocked(now)
	if m.stopped == nil {
		m.stopped = map[string]stoppedOutcome{}
	}
	if len(m.stopped) >= maxStoppedOutcomes {
		var oldest string
		for id, outcome := range m.stopped {
			if oldest == "" || outcome.expires.Before(m.stopped[oldest].expires) {
				oldest = id
			}
		}
		delete(m.stopped, oldest)
	}
	m.stopped[service.RegistrationID] = stoppedOutcome{
		service: service.Name, owner: owner, target: target,
		expires: now.Add(stoppedOutcomeLifetime), err: err,
	}
}

// RetirementError retains failures from background sweeps and joined workers
// after their registrations have been released.
func (m *Manager) RetirementError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retirementErr
}

// joined cancellation does not erase an independent worker or cleanup failure.
func independentWorkerFailure(err error, canceled bool) error {
	if err == nil || err == context.Canceled || canceled && err == ErrRegistrationStale {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var failures []error
		for _, cause := range joined.Unwrap() {
			failures = append(failures, independentWorkerFailure(cause, canceled))
		}
		return errors.Join(failures...)
	}
	if cause := errors.Unwrap(err); cause != nil {
		filtered := independentWorkerFailure(cause, canceled)
		if filtered == nil {
			return nil
		}
		if errors.Is(cause, context.Canceled) || canceled && errors.Is(cause, ErrRegistrationStale) {
			return filtered
		}
	}
	return err
}

// TargetChanged invalidates only the current registration's current run. worker
// configuration is captured before provisioning and cannot supply its run number.
func (m *Manager) TargetChanged(name, id, target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	service := m.serviceLocked(name)
	if m.closed || service == nil || service.RegistrationID != id || service.Target != target {
		return
	}
	if service.invalidateTarget(time.Now().UTC()) {
		m.emitLocked("service.readiness", service)
		if changed := m.targetChanges[id]; changed != nil {
			select {
			case changed <- struct{}{}:
			default:
			}
		}
	}
}

// the run owner joins its current probe before acting on a replacement event.
// a coalesced event means check the latest target, not replay each old identity.
func (m *Manager) watchTargetChanges(id string) (<-chan struct{}, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.targetChanges == nil {
		m.targetChanges = map[string]chan struct{}{}
	}
	changed := make(chan struct{}, 1)
	m.targetChanges[id] = changed
	return changed, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.targetChanges[id] == changed {
			delete(m.targetChanges, id)
		}
	}
}

// sweep uses both SDK renewal and process liveness; a TCP listener alone never
// grants ownership. expiration rejects old observations before cleanup.
func (m *Manager) Sweep(alive func(int) bool) bool {
	m.mu.Lock()
	m.pruneStoppedLocked(time.Now())
	type expired struct{ id, owner string }
	var entries []expired
	for name, reg := range m.registrations {
		if time.Now().After(reg.expires) || alive != nil && !alive(reg.pid) {
			entries = append(entries, expired{m.serviceLocked(name).RegistrationID, reg.owner})
		}
	}
	m.mu.Unlock()
	for _, entry := range entries {
		_ = m.Unregister(entry.id, entry.owner)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeErr != nil || m.preparing == 0 && !m.idleSince.IsZero() && time.Since(m.idleSince) >= CleanupGrace
}

func (m *Manager) Close() {
	m.closeOnce.Do(m.close)
}

func (m *Manager) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	type entry struct{ id, owner string }
	var entries []entry
	for name, reg := range m.registrations {
		m.shutdownLocked(reg)
		if reg.cleanup != nil && m.ShutdownDeadline != nil {
			reg.cleanup.limit(m.ShutdownDeadline())
		}
		if reg.cancel != nil {
			reg.cancel()
		}
		entries = append(entries, entry{m.serviceLocked(name).RegistrationID, reg.owner})
	}
	m.mu.Unlock()
	for _, entry := range entries {
		if err := m.Unregister(entry.id, entry.owner); err != nil && !errors.Is(err, ErrRegistrationStopped) {
			m.mu.Lock()
			m.retirementErr = errors.Join(m.retirementErr, err)
			m.mu.Unlock()
		}
	}
	m.mu.Lock()
	m.emitLocked("runtime.stopped", nil)
	m.mu.Unlock()
}

// shutdownLocked records the first stop's deadline before canceling its worker.
func (m *Manager) shutdownLocked(reg *registration) time.Time {
	var parent time.Time
	if (m.closed || m.ctx.Err() != nil) && m.ShutdownDeadline != nil {
		parent = m.ShutdownDeadline()
	}
	until := reg.shutdownUntil
	if until.IsZero() {
		until = time.Now().Add(10 * time.Second)
	}
	if !parent.IsZero() && parent.Before(until) {
		until = parent
	}
	m.limitShutdownLocked(reg, until)
	return reg.shutdownUntil
}

// the registration owns this fence before its first stop. a tighter limit
// interrupts contexts already handed to service drain and allocation cleanup.
func (m *Manager) shutdownContextLocked(reg *registration) context.Context {
	if reg.shutdown == nil {
		reg.shutdown, reg.stopShutdown = context.WithCancelCause(context.WithoutCancel(m.ctx))
	}
	return reg.shutdown
}

func (m *Manager) limitShutdownLocked(reg *registration, until time.Time) {
	m.shutdownContextLocked(reg)
	if !reg.shutdownUntil.IsZero() && !until.Before(reg.shutdownUntil) {
		return
	}
	reg.stopShutdownTimer()
	reg.shutdownUntil = until
	done, cancel := make(chan struct{}), reg.stopShutdown
	reg.shutdownDone = done
	reg.shutdownTimer = time.AfterFunc(time.Until(until), func() {
		defer close(done)
		cancel(context.DeadlineExceeded)
	})
	if !time.Now().Before(until) {
		cancel(context.DeadlineExceeded)
	}
}

func (reg *registration) stopShutdownTimer() {
	if reg.shutdownTimer != nil {
		if reg.shutdownTimer.Stop() {
			close(reg.shutdownDone)
		}
		<-reg.shutdownDone
		reg.shutdownTimer, reg.shutdownDone = nil, nil
	}
}

func (reg *registration) finishShutdown() {
	reg.stopShutdownTimer()
	if reg.stopShutdown != nil {
		reg.stopShutdown(context.Canceled)
	}
	reg.shutdown, reg.stopShutdown = nil, nil
}

// PublicationShutdownContext does not start a budget. its exact registration's
// owner cancels it with DeadlineExceeded when the current stop limit expires.
func (m *Manager) PublicationShutdownContext(id string) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, reg := range m.registrations {
		if service := m.serviceLocked(name); service != nil && service.RegistrationID == id {
			return m.shutdownContextLocked(reg)
		}
	}
	return context.WithoutCancel(m.ctx)
}

// PublicationCleanupContext is borrowed only by the manager's joined Cleanup
// callback. explicit retries can own a new bound without reviving the worker or
// extending its original automatic shutdown fence.
func (m *Manager) PublicationCleanupContext(id string) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, reg := range m.registrations {
		if service := m.serviceLocked(name); service != nil && service.RegistrationID == id && reg.cleanup != nil {
			return reg.cleanup.ctx
		}
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(m.ctx))
	cancel()
	return ctx
}

// PublicationShutdownDeadline keeps worker drain, automatic cleanup, and its terminal
// journal on the registration's original budget. an unbound local journal still
// needs a cleanup budget; this value grants no registration or serving authority.
func (m *Manager) PublicationShutdownDeadline(id string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, reg := range m.registrations {
		if service := m.serviceLocked(name); service != nil && service.RegistrationID == id {
			return m.shutdownLocked(reg)
		}
	}
	until := time.Now().Add(10 * time.Second)
	if (m.closed || m.ctx.Err() != nil) && m.ShutdownDeadline != nil {
		if parent := m.ShutdownDeadline(); parent.Before(until) {
			until = parent
		}
	}
	return until
}

// LimitShutdown narrows an exact registration's stop deadline at the private API.
// retained cleanup selects a separate explicit retry budget instead. neither
// operation extends the original automatic stop or changes its target.
func (m *Manager) LimitShutdown(id, owner, target string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, found := m.stoppedOutcomeLocked(id, owner, target); found {
		return nil
	}
	service, reg := m.findUnregisterLocked(id, owner)
	if reg == nil || service.Target != "" && service.Target != target || reg.cleanupTarget != nil && *reg.cleanupTarget != target {
		return ErrRegistrationStale
	}
	if reg.cleanupPending {
		if reg.cleanup != nil {
			reg.cleanup.limit(until)
			if !reg.cleanup.detached && until.Before(reg.shutdownUntil) {
				m.limitShutdownLocked(reg, until)
			}
			return nil
		}
		// this only selects the next explicit retry's bound. sweeps and process
		// shutdown continue using the original automatic deadline.
		if reg.retryUntil.IsZero() || until.Before(reg.retryUntil) {
			reg.retryUntil = until
		}
		return nil
	}
	current := m.shutdownLocked(reg)
	if until.Before(current) {
		m.limitShutdownLocked(reg, until)
	}
	return nil
}
