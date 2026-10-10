package clientruntime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

type AdHocRun func(context.Context, privateprotocol.AdHocRegister, func(privateprotocol.AdHocStatus)) error

type adHocEntry struct {
	owner   string
	pid     int
	expires time.Time
	digest  [32]byte
	status  privateprotocol.AdHocStatus
	cancel  context.CancelFunc
	done    chan struct{}
	release func()
}

// AdHocManager keeps each invocation tied to one live owner and bound listener.
// only nonsecret status values leave the in-memory worker.
type AdHocManager struct {
	mu      sync.Mutex
	ctx     context.Context
	run     AdHocRun
	alive   func(int) bool
	hold    func() func()
	entries map[string]*adHocEntry
	closed  bool
}

func NewAdHocManager(ctx context.Context, run AdHocRun, alive func(int) bool, hold func() func()) *AdHocManager {
	return &AdHocManager{ctx: ctx, run: run, alive: alive, hold: hold, entries: make(map[string]*adHocEntry)}
}

func (m *AdHocManager) Register(request privateprotocol.AdHocRegister) (privateprotocol.AdHocStatus, error) {
	if request.Version != privateprotocol.Version || !opaqueid.Valid(request.RegistrationID, opaqueid.InvocationPrefix) ||
		!privateprotocol.ValidOwner(request.Owner) || request.PID <= 0 || m.alive != nil && !m.alive(request.PID) ||
		request.AllowAllIPs && len(request.AllowIP) != 0 {
		return privateprotocol.AdHocStatus{}, errors.New("invalid ad-hoc registration")
	}
	canonical, err := localproxy.NormalizeTarget(request.Target)
	if err != nil || canonical != request.Target {
		return privateprotocol.AdHocStatus{}, errors.New("ad-hoc target must be canonical")
	}
	if _, _, _, err := credentials.ParseEphemeralCredential(credentials.EphemeralCredential(request.Credential)); err != nil {
		return privateprotocol.AdHocStatus{}, errors.New("ad-hoc credential is invalid")
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > privateprotocol.MaxBytes {
		return privateprotocol.AdHocStatus{}, errors.New("ad-hoc registration is too large")
	}
	digest := sha256.Sum256(encoded)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return privateprotocol.AdHocStatus{}, ErrRegistrationStale
	}
	if existing := m.entries[request.RegistrationID]; existing != nil {
		if existing.owner != request.Owner || existing.pid != request.PID || existing.digest != digest {
			return privateprotocol.AdHocStatus{}, ErrOwnerConflict
		}
		existing.expires = time.Now().Add(LeaseDuration)
		return existing.status, nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	entry := &adHocEntry{owner: request.Owner, pid: request.PID, expires: time.Now().Add(LeaseDuration), digest: digest,
		status: privateprotocol.AdHocStatus{Version: privateprotocol.Version, RegistrationID: request.RegistrationID, State: "starting"},
		cancel: cancel, done: make(chan struct{}), release: func() {}}
	if m.hold != nil {
		entry.release = m.hold()
	}
	m.entries[request.RegistrationID] = entry
	go m.publish(ctx, request, entry)
	return entry.status, nil
}

func (m *AdHocManager) publish(ctx context.Context, request privateprotocol.AdHocRegister, entry *adHocEntry) {
	defer close(entry.done)
	err := m.run(ctx, request, func(status privateprotocol.AdHocStatus) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.entries[request.RegistrationID] == entry && status.Version == privateprotocol.Version &&
			status.RegistrationID == request.RegistrationID && entry.status.State != "failed" {
			entry.status = status
		}
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries[request.RegistrationID] != entry || entry.status.State == "failed" {
		return
	}
	entry.status.State = "stopped"
	if err != nil && ctx.Err() == nil {
		entry.status.State, entry.status.FailureCode = "failed", "runtime.publication_failed"
		if reason, _, ok := failure.Describe(err); ok {
			entry.status.FailureCode = string(reason)
		}
	}
}

func (m *AdHocManager) Status(registrationID, owner string) (privateprotocol.AdHocStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entries[registrationID]
	if m.closed || entry == nil || entry.owner != owner || time.Now().After(entry.expires) {
		return privateprotocol.AdHocStatus{}, ErrRegistrationStale
	}
	return entry.status, nil
}

func (m *AdHocManager) Renew(registrationID, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entries[registrationID]
	if m.closed || entry == nil || entry.owner != owner || time.Now().After(entry.expires) || m.alive != nil && !m.alive(entry.pid) {
		return ErrRegistrationStale
	}
	entry.expires = time.Now().Add(LeaseDuration)
	return nil
}

func (m *AdHocManager) Unregister(registrationID, owner string) error {
	m.mu.Lock()
	entry := m.entries[registrationID]
	if entry == nil || entry.owner != owner {
		m.mu.Unlock()
		return ErrRegistrationStale
	}
	delete(m.entries, registrationID)
	entry.cancel()
	m.mu.Unlock()
	<-entry.done
	entry.release()
	return nil
}

func (m *AdHocManager) Sweep() {
	m.mu.Lock()
	var expired []*adHocEntry
	for id, entry := range m.entries {
		if time.Now().After(entry.expires) || m.alive != nil && !m.alive(entry.pid) {
			entry.status.State, entry.status.FailureCode = "failed", "runtime.registration_stale"
			delete(m.entries, id)
			entry.cancel()
			expired = append(expired, entry)
		}
	}
	m.mu.Unlock()
	for _, entry := range expired {
		<-entry.done
		entry.release()
	}
}

func (m *AdHocManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	var entries []*adHocEntry
	for id, entry := range m.entries {
		delete(m.entries, id)
		entry.cancel()
		entries = append(entries, entry)
	}
	m.mu.Unlock()
	for _, entry := range entries {
		<-entry.done
		entry.release()
	}
}
