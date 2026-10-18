package clientruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

const LeaseDuration = 20 * time.Second
const CleanupGrace = 10 * time.Second

type Run func(context.Context, Service, func(uint64, bool) error) error

type registration struct {
	owner   string
	pid     int
	expires time.Time
	cancel  context.CancelFunc
	done    chan struct{}
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
	idleSince     time.Time
	preparing     int
	closed        bool
	closeOnce     sync.Once
	writeErr      error
}

func New(ctx context.Context, project string, database *clientstate.Database, services []Service, run Run) (*Manager, error) {
	if database == nil {
		return nil, errors.New("clientruntime: open client state is required")
	}
	previous, err := ReadSnapshotFrom(ctx, database, project)
	if err != nil {
		return nil, err
	}
	m := &Manager{ctx: ctx, database: database, run: run, registrations: map[string]*registration{}, idleSince: time.Now(), snapshot: previous}
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := CommitSnapshot(ctx, m.database, &m.snapshot, kind, service); err != nil {
		m.writeErr = err
	}
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := m.snapshot
	copy.Services = slices.Clone(copy.Services)
	for index := range copy.Services {
		if value := copy.Services[index].Observation; value != nil {
			observation := *value
			copy.Services[index].Observation = &observation
		}
	}
	copy.Events = slices.Clone(copy.Events)
	// publication writers share the journal but do not take the manager lock.
	if latest, err := ReadSnapshotFrom(context.Background(), m.database, m.snapshot.Project); err == nil {
		copy.Cursor, copy.ObservedAt, copy.Publications, copy.Events = latest.Cursor, latest.ObservedAt, latest.Publications, latest.Events
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
		if err := m.unregister(entry.id, entry.owner); err != nil {
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
				next[index].Ready, next[index].Observation = false, nil
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
			err := m.unregister(id, previousOwner)
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
	service.RegistrationID = "reg_" + hex.EncodeToString(bytes)
	service.Target, service.Framework, service.PublishRunNumber = "", "", 0
	service.Registered, service.Routable, service.Ready, service.Observation = false, false, false, nil
	service.PublicURL, service.Failure = publicURL, ""
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
			if reg := m.registrations[service.Name]; reg != nil && reg.owner == owner && time.Now().Before(reg.expires) && (m.Alive == nil || m.Alive(reg.pid)) {
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
		_, targetErr = localproxy.ParseCanonicalTarget(target)
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
		service.Registered, service.Routable, service.Ready = false, false, false
		service.Observation = nil
		m.emitLocked("service.replacing", service)
		reg.cancel()
		done := reg.done
		m.mu.Unlock()
		<-done
		m.mu.Lock()
	}
	service.Registered, service.Routable, service.Ready = true, false, false
	service.Target, service.Framework, service.Failure = target, framework, ""
	service.PublishRunNumber, service.Observation = 0, nil
	service.ProvisioningStage = ""
	reg.expires = time.Now().Add(LeaseDuration)
	ctx, cancel := context.WithCancel(m.ctx)
	reg.cancel, reg.done = cancel, make(chan struct{})
	copy, done := *service, reg.done
	m.emitLocked("service.registered", service)
	if err := m.writeErr; err != nil {
		cancel()
		close(done)
		reg.cancel = nil
		service.Registered = false
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	go func() {
		defer close(done)
		err := m.run(ctx, copy, func(run uint64, routable bool) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			current, active := m.findLocked(id, owner)
			if active == nil || active.done != done || current.Target != copy.Target || ctx.Err() != nil {
				return ErrRegistrationStale
			}
			return m.publishedLocked(id, run, routable)
		})
		m.mu.Lock()
		defer m.mu.Unlock()
		current := m.serviceLocked(copy.Name)
		if current == nil || current.RegistrationID != id || reg.done != done {
			return
		}
		current.Routable, current.Ready = false, false
		current.Observation, current.ProvisioningStage = nil, ""
		reg.cancel = nil
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

func (m *Manager) Published(id string, run uint64, routable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publishedLocked(id, run, routable)
}

func (m *Manager) publishedLocked(id string, run uint64, routable bool) error {
	if m.closed {
		return ErrRegistrationStale
	}
	for index := range m.snapshot.Services {
		service := &m.snapshot.Services[index]
		reg := m.registrations[service.Name]
		if service.RegistrationID != id || !service.Registered || reg == nil || time.Now().After(reg.expires) {
			continue
		}
		if run < service.PublishRunNumber {
			return ErrRegistrationStale
		}
		if run != service.PublishRunNumber || !routable {
			service.Ready, service.Observation = false, nil
			if run != service.PublishRunNumber {
				service.ProvisioningStage = ""
			}
		}
		service.PublishRunNumber, service.Routable = run, routable
		if routable {
			service.Failure = ""
			service.ProvisioningStage = ""
		}
		m.emitLocked("service.publication", service)
		return m.writeErr
	}
	return ErrRegistrationStale
}

func (m *Manager) Current(name, id, target string, run uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	service := m.serviceLocked(name)
	reg := m.registrations[name]
	return !m.closed && service != nil && reg != nil && time.Now().Before(reg.expires) && (m.Alive == nil || m.Alive(reg.pid)) && service.Registered && service.RegistrationID == id && service.Target == target && (run == 0 || service.PublishRunNumber == run)
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
	if service == nil || !service.Registered || service.Routable || service.RegistrationID != registrationID || service.PublishRunNumber != run || service.ProvisioningStage == stage {
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
		if service.RegistrationID != observation.RegistrationID || service.PublishRunNumber != observation.PublishRunNumber || !service.Registered || !service.Routable || observation.PublishRunNumber == 0 {
			continue
		}
		if observation.Readiness != service.Readiness {
			return false
		}
		if observation.Target != "" && service.Target != observation.Target {
			return false
		}
		reg := m.registrations[service.Name]
		if reg == nil || time.Now().After(reg.expires) || m.Alive != nil && !m.Alive(reg.pid) {
			return false
		}
		if service.Observation != nil && observation.CheckedAt.Before(service.Observation.CheckedAt) {
			return false
		}
		service.Ready, service.Observation = observation.Ready, &observation
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
	return m.unregister(id, owner)
}

func (m *Manager) UnregisterTarget(id, owner, target string) error {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	service, reg := m.findLocked(id, owner)
	if reg == nil || service.Registered && service.Target != target {
		m.mu.Unlock()
		return ErrRegistrationStale
	}
	m.mu.Unlock()
	return m.unregister(id, owner)
}

func (m *Manager) unregister(id, owner string) error {
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
	service.Registered, service.Routable, service.Ready = false, false, false
	service.ProvisioningStage = ""
	service.Observation = nil
	m.emitLocked("service.unregistered", service)
	if reg.cancel != nil {
		reg.cancel()
	}
	done := reg.done
	m.mu.Unlock()
	if done != nil {
		<-done
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.registrations, service.Name)
	service.RegistrationID, service.Target, service.TunnelID = "", "", ""
	if len(m.registrations) == 0 {
		m.idleSince = time.Now()
	}
	m.emitLocked("service.stopped", service)
	return m.writeErr
}

// sweep uses both SDK renewal and process liveness; a TCP listener alone never
// grants ownership. expiration rejects old observations before cleanup.
func (m *Manager) Sweep(alive func(int) bool) bool {
	m.mu.Lock()
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
		entries = append(entries, entry{m.serviceLocked(name).RegistrationID, reg.owner})
	}
	m.mu.Unlock()
	for _, entry := range entries {
		_ = m.Unregister(entry.id, entry.owner)
	}
	m.mu.Lock()
	m.emitLocked("runtime.stopped", nil)
	m.mu.Unlock()
}
