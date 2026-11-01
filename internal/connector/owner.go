package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/kubeconfig"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/observability"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

type preparedConnection struct {
	service         controlv1.Service
	connection      connectorruntime.Connection
	kubeSource      kubeconfig.Source
	kubePlan        kubeconfig.Plan
	kubeResult      kubeconfig.Result
	err             error
	listener        *connectorruntime.ListenerSwitch
	ready           bool
	cancel          context.CancelFunc
	control         connectorstream.Control
	authorizedUntil time.Time
	sessionID       string
}

type connectorConnectionBackend struct {
	connectorConnectionSession
	openSession                                            SessionOpener
	project                                                projectConfiguration
	scope                                                  connectorruntime.Context
	stateDir, assertion, directory, executable, runnerTemp string
	httpClient                                             *http.Client
	acquisition                                            workloadmanifest.Acquisition
	prepared                                               map[string]*preparedConnection
	initialServices                                        []string
	services                                               map[string]controlv1.Service
	metadata                                               meta.PublicMetadata
	lifetime                                               context.Context
	kubeMu                                                 sync.Mutex
	serviceGates                                           map[string]chan struct{}
	snapshot                                               atomic.Pointer[connectorPreparedSnapshot]
	closed                                                 bool
	cleanupContext                                         context.Context
	operations                                             sync.WaitGroup
	cancel                                                 context.CancelFunc
	workers                                                sync.WaitGroup
	mu                                                     sync.Mutex
	cleanupErr                                             error
	parentPID                                              int
	kubeOptions                                            StartOptions
	sessionKubePlan                                        kubeconfig.Plan
	sessionKubeResult                                      kubeconfig.Result
}

// session state is independent of configured scope and service coordination.
// mu protects publication; sessionGate serializes exchanges without blocking readers.
type connectorConnectionSession struct {
	human            *Session
	teamID           string
	workload         *workload.Client
	replacement      *workload.Client
	replacementScope connectorruntime.Context
	deadline         time.Time
	sessionGate      chan struct{}
	verification     *connectorruntime.AssertionVerification
	assertions       map[string]connectorruntime.AssertionVerification
	assertionChecks  map[string]time.Time
	verifiedSession  string
}

// the configured scope never changes with listener readiness or session renewal.
// snapshots contain only published values; readers never join network work.
type connectorPreparedSnapshot struct {
	metadata     meta.PublicMetadata
	verification *connectorruntime.AssertionVerification
	assertions   map[string]connectorruntime.AssertionVerification
	connections  map[string]connectorruntime.Connection
	errors       map[string]error
}

func (b *connectorConnectionBackend) publishLocked() {
	s := &connectorPreparedSnapshot{metadata: b.metadata, connections: map[string]connectorruntime.Connection{}, errors: map[string]error{}}
	s.assertions = make(map[string]connectorruntime.AssertionVerification, len(b.assertions))
	for digest, proof := range b.assertions {
		s.assertions[digest] = proof
	}
	if b.verification != nil {
		v := *b.verification
		s.verification = &v
	}
	for name, p := range b.prepared {
		if !p.ready {
			continue
		}
		service, allowed := b.services[name]
		if !allowed || service.Id != p.service.Id || service.Protocol != p.service.Protocol || service.Endpoint == nil || p.service.Endpoint == nil || *service.Endpoint != *p.service.Endpoint {
			continue
		}
		if p.err != nil {
			s.errors[name] = p.err
			continue
		}
		if b.closed {
			s.errors[name] = connectorruntime.ErrExpired
			continue
		}
		deadline := b.deadline
		if b.workload != nil {
			session, err := b.workload.Session()
			if err != nil || session.Id != p.sessionID {
				continue
			}
			if !slices.Contains(session.ServiceIds, p.service.Id) {
				continue
			}
			deadline = minTime(deadline, session.LeaseExpiresAt)
		}
		c := p.connection
		c.ExpiresAt = deadline
		if p.service.Protocol != controlv1.Tcp {
			c.SSL = &connectorruntime.TLSOptions{ServerName: p.service.Endpoint.Hostname, RejectUnauthorized: true}
		}
		s.connections[name] = c
	}
	b.snapshot.Store(s)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (b *connectorConnectionBackend) begin(ctx context.Context) (context.Context, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil, connectorruntime.ErrExpired
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	b.operations.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := func() bool { return false }
	if b.lifetime != nil {
		stop = context.AfterFunc(b.lifetime, cancel)
	}
	return ctx, func() { stop(); cancel(); b.operations.Done() }, nil
}

func (b *connectorConnectionBackend) cleanup() context.Context {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cleanupContext != nil {
		return b.cleanupContext
	}
	return context.Background()
}

func (b *connectorConnectionBackend) Start(ctx context.Context) (meta.PublicMetadata, time.Time, error) {
	b.prepared = map[string]*preparedConnection{}
	b.teamID = b.scope.TeamID
	lifetime, cancel := context.WithCancel(observability.Independent(context.WithoutCancel(ctx)))
	b.cancel = cancel
	b.lifetime = lifetime
	metadata := meta.Metadata{Version: meta.Version, Services: map[string]meta.Service{}}
	services := map[string]controlv1.Service{}
	if b.scope.Workload != "" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		client, err := workload.NewWithKey(b.scope.Server, b.httpClient, key)
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		b.workload = client
		identity, err := client.IdentifyPolicy(ctx, b.scope.TeamID, b.scope.ProjectKey, b.scope.SourceID, b.scope.Workload, b.assertion)
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		selected := []string{}
		for _, name := range b.scope.Services {
			if slices.Contains(identity.Services, name) {
				selected = append(selected, name)
			}
		}
		if len(selected) == 0 {
			return meta.PublicMetadata{}, time.Time{}, connectorruntime.ErrUnauthorized
		}
		requested := b.scope
		requested.Services = selected
		assertion := b.assertion
		session, err := exchangeConnectionWorkload(ctx, client, requested, assertion)
		b.assertion = "" // neither the assertion nor GitHub's request bearer survives exchange.
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		b.deadline = session.ExpiresAt
		if session.Binding != identity.Binding {
			return meta.PublicMetadata{}, time.Time{}, connectorruntime.ErrUnauthorized
		}
		b.rememberAssertion(assertion, identity.AssertionExpiresAt, session)
		if session.ExpiresAt.After(time.Now().Add(b.project.Config.Workloads[b.scope.Workload].DurationLimit())) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
			return meta.PublicMetadata{}, time.Time{}, connectorruntime.ErrExpired
		}
		inventory, err := client.ListServices(ctx)
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		for _, service := range inventory.Services {
			if _, duplicate := services[service.Service]; duplicate {
				return meta.PublicMetadata{}, time.Time{}, connectorruntime.ErrInvalid
			}
			services[service.Service] = controlv1.Service{Id: service.Id, Name: service.Service, TeamId: session.TeamId, Protocol: service.Protocol, Enabled: true, Endpoint: &service.Endpoint, KubernetesAuth: service.KubernetesAuth}
		}
	} else {
		session, err := b.openSession(ctx, SessionOptions{ServerURL: b.scope.Server, StateDir: b.stateDir, ProjectTeam: b.scope.TeamID}, "tnl connect", io.Discard)
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		b.human = session
		b.deadline = time.Now().Add(time.Hour)
		membership, err := session.currentMembership(ctx)
		if err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
		b.teamID = membership.TeamId
		for _, name := range b.scope.Services {
			service, err := Select(ctx, session.authenticated.Control, b.project.Project, name, membership.TeamId)
			if err != nil {
				continue // one service's denial does not prevent another service's preparation.
			}
			services[name] = service
		}
	}
	for _, name := range b.scope.Services {
		service, ok := services[name]
		if !ok {
			continue
		}
		if err := ValidateService(service); err != nil {
			delete(services, name)
			continue
		}
		endpoint := service.Endpoint
		if string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
			delete(services, name)
			continue
		}
		value, err := meta.NewEndpoint(endpoint.Hostname, endpoint.Hostname, string(service.Protocol), endpoint.Port, endpoint.Public)
		if err != nil {
			delete(services, name)
			continue
		}
		metadata.Services[name] = value
		if metadata.Namespace == "" {
			metadata.Namespace = endpoint.Hostname
		}
	}
	if err := metadata.Validate(); err != nil {
		return meta.PublicMetadata{}, time.Time{}, err
	}
	b.services = services
	b.metadata = metadata.Public(false)
	b.mu.Lock()
	b.publishLocked()
	b.mu.Unlock()
	// caller-prepared CLI owners retain their aggregate readiness contract.
	// application-owned SDK processes prepare each service on its own IPC read.
	for _, name := range b.initialServices {
		if _, err := b.Connect(ctx, name); err != nil {
			return meta.PublicMetadata{}, time.Time{}, err
		}
	}
	return b.metadata, b.deadline, nil
}

func (b *connectorConnectionBackend) Connect(ctx context.Context, name string) (connectorruntime.Connection, error) {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return connectorruntime.Connection{}, err
	}
	defer finish()
	b.mu.Lock()
	if b.serviceGates == nil {
		b.serviceGates = map[string]chan struct{}{}
	}
	gate := b.serviceGates[name]
	if gate == nil {
		gate = make(chan struct{}, 1)
		b.serviceGates[name] = gate
	}
	b.mu.Unlock()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return connectorruntime.Connection{}, ctx.Err()
	}
	if _, err := b.healthy(); err != nil {
		return connectorruntime.Connection{}, err
	}
	b.mu.Lock()
	service, found := b.services[name]
	p := b.prepared[name]
	client := b.workload
	authorizedUntil := time.Time{}
	if p != nil {
		authorizedUntil = p.authorizedUntil
	}
	b.mu.Unlock()
	if !found || ValidateService(service) != nil || string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return connectorruntime.Connection{}, connectorruntime.ErrInvalid
	}
	if p != nil && time.Now().Before(authorizedUntil) {
		if snapshot, err := b.Prepared(name); err == nil {
			return snapshot, nil
		}
	}
	validUntil := time.Now().Add(30 * time.Second)
	if client != nil {
		authorization, err := client.CheckService(ctx, service.Id)
		if err != nil {
			return connectorruntime.Connection{}, err
		}
		if authorization.ValidUntil.Before(validUntil) {
			validUntil = authorization.ValidUntil
		}
	}
	b.mu.Lock()
	failed := p != nil && p.err != nil
	if p != nil && client != nil {
		session, err := client.Session()
		failed = failed || err != nil || session.Id != p.sessionID
	}
	b.mu.Unlock()
	// refresh approved metadata only at an explicit preparation boundary. the
	// service ID stays fenced by the current session's immutable authorization.
	if p == nil || !p.ready || failed || !time.Now().Before(authorizedUntil) {
		fresh, err := b.refreshService(ctx, name, service, client)
		if err != nil {
			return connectorruntime.Connection{}, err
		}
		if p != nil && (fresh.Endpoint == nil || p.service.Endpoint == nil || *fresh.Endpoint != *p.service.Endpoint) {
			failed = true
		}
		service = fresh
	}
	if p == nil || !p.ready || failed {
		var err error
		p, err = b.prepareService(ctx, name, p, service, client)
		if err != nil {
			return connectorruntime.Connection{}, err
		}
	}
	b.mu.Lock()
	err = p.err
	b.mu.Unlock()
	if err != nil {
		return connectorruntime.Connection{}, err
	}
	if b.human != nil && p.control != nil {
		if _, err := p.control.ResolveService(ctx, p.service.Id); err != nil {
			return connectorruntime.Connection{}, err
		}
	}
	b.mu.Lock()
	if b.workload != client || b.closed {
		b.mu.Unlock()
		return connectorruntime.Connection{}, connectorruntime.ErrUnprepared
	}
	p.authorizedUntil = validUntil
	b.publishLocked()
	b.mu.Unlock()
	return b.Prepared(name)
}

func (b *connectorConnectionBackend) refreshService(ctx context.Context, name string, approved controlv1.Service, client *workload.Client) (controlv1.Service, error) {
	service := approved
	if client != nil {
		inventory, err := client.ListServices(ctx)
		if err != nil {
			return service, err
		}
		found := false
		for _, s := range inventory.Services {
			if s.Service != name || s.Id != approved.Id {
				continue
			}
			if found {
				return service, connectorruntime.ErrInvalid
			}
			found = true
			service = controlv1.Service{Id: s.Id, Name: name, TeamId: approved.TeamId, Protocol: s.Protocol, Enabled: true, Endpoint: &s.Endpoint, KubernetesAuth: s.KubernetesAuth}
		}
		if !found {
			return service, connectorruntime.ErrUnauthorized
		}
	} else if b.human != nil {
		var err error
		service, err = Select(ctx, b.human.authenticated.Control, b.project.Project, name, b.teamID)
		if err != nil {
			return service, err
		}
		if service.Id != approved.Id {
			return service, connectorruntime.ErrUnauthorized
		}
	}
	if ValidateService(service) != nil || string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return service, connectorruntime.ErrInvalid
	}
	endpoint := service.Endpoint
	value, err := meta.NewEndpoint(endpoint.Hostname, endpoint.Hostname, string(service.Protocol), endpoint.Port, endpoint.Public)
	if err != nil {
		return service, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.workload != client || b.closed {
		return service, connectorruntime.ErrUnprepared
	}
	b.services[name] = service
	metadata := b.metadata
	metadata.Services = make(map[string]meta.Service, len(b.metadata.Services))
	for key, s := range b.metadata.Services {
		metadata.Services[key] = s
	}
	metadata.Services[name] = value
	if approved.Endpoint != nil && metadata.Namespace == approved.Endpoint.Hostname {
		metadata.Namespace = value.Namespace
	}
	b.metadata = metadata
	b.publishLocked()
	return service, nil
}

// Prepared is a local read only: no provider/control requests, key creation,
// listener setup or repair. an unprepared sibling must be explicitly awaited.
func (b *connectorConnectionBackend) Prepared(name string) (connectorruntime.Connection, error) {
	p, err := b.Snapshot(name)
	return p.Connection, err
}

func (b *connectorConnectionBackend) Snapshot(name string) (connectorruntime.Prepared, error) {
	return b.SnapshotFor(name, "")
}

func (b *connectorConnectionBackend) SnapshotFor(name, assertion string) (connectorruntime.Prepared, error) {
	s := b.snapshot.Load()
	if s == nil {
		b.mu.Lock()
		b.publishLocked()
		s = b.snapshot.Load()
		b.mu.Unlock()
	}
	if err := s.errors[name]; err != nil {
		return connectorruntime.Prepared{}, err
	}
	c, ok := s.connections[name]
	if !ok {
		return connectorruntime.Prepared{}, connectorruntime.ErrUnprepared
	}
	if !c.ExpiresAt.After(time.Now()) {
		return connectorruntime.Prepared{}, connectorruntime.ErrExpired
	}
	var verification *connectorruntime.AssertionVerification
	if s.verification != nil && s.verification.ExpiresAt.After(time.Now()) {
		v := *s.verification
		verification = &v
	}
	if c.SSL != nil {
		ssl := *c.SSL
		c.SSL = &ssl
	}
	if assertion != "" {
		digest := sha256.Sum256([]byte(assertion))
		proof, found := s.assertions[hex.EncodeToString(digest[:])]
		if !found || !proof.ExpiresAt.After(time.Now()) {
			return connectorruntime.Prepared{}, connectorruntime.ErrUnprepared
		}
		verification = &proof
	}
	return connectorruntime.Prepared{Schema: 1, ProjectRuntime: s.metadata, Connection: c, Verification: verification}, nil
}
func (b *connectorConnectionBackend) healthy() (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.human != nil && b.workload == nil {
		b.deadline = time.Now().Add(time.Hour)
		b.publishLocked()
	}
	if !b.deadline.After(time.Now()) {
		return time.Time{}, connectorruntime.ErrExpired
	}
	return b.deadline, nil
}
func (b *connectorConnectionBackend) Renew(ctx context.Context) (time.Time, error) {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer finish()
	if b.parentPID > 0 {
		process, err := os.FindProcess(b.parentPID)
		if err != nil || process.Signal(syscall.Signal(0)) != nil {
			return time.Time{}, connectorruntime.ErrExpired
		}
	}
	if _, err := b.healthy(); err != nil {
		return time.Time{}, err
	}
	b.mu.Lock()
	client := b.workload
	currentDeadline := b.deadline
	b.mu.Unlock()
	if client != nil {
		session, err := client.Renew(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if session.ExpiresAt.After(currentDeadline) || !session.LeaseExpiresAt.After(time.Now()) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
			return time.Time{}, connectorruntime.ErrExpired
		}
		b.mu.Lock()
		if b.workload == client && session.ExpiresAt.Before(b.deadline) {
			b.deadline = session.ExpiresAt
		}
		deadline := b.deadline
		b.publishLocked()
		b.mu.Unlock()
		return deadline, nil
	}
	b.mu.Lock()
	b.deadline = time.Now().Add(time.Hour)
	deadline := b.deadline
	b.publishLocked()
	b.mu.Unlock()
	return deadline, nil
}

// process lifetime belongs to the application; session deadlines remain in
// snapshots and data-plane admission, not in the local capability's lifetime.
func (b *connectorConnectionBackend) Persistent() bool {
	return b.scope.Workload == "" || b.parentPID > 0
}

func (b *connectorConnectionBackend) OwnerAlive() bool {
	if b.parentPID <= 0 {
		return true
	}
	p, err := os.FindProcess(b.parentPID)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

func (b *connectorConnectionBackend) Attach(ctx context.Context, assertion string) error {
	return b.attach(ctx, assertion, false)
}

func (b *connectorConnectionBackend) UseAssertion(ctx context.Context, assertion string) error {
	return b.attach(ctx, assertion, true)
}

func (b *connectorConnectionBackend) attach(ctx context.Context, assertion string, reuse bool) error {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	// verified warm requests do not join unrelated assertion acquisition or
	// exchange. the cached proof still belongs to this exact current session.
	if reuse && assertion != "" && b.reuseAssertion(assertion) {
		return nil
	}
	b.mu.Lock()
	if b.sessionGate == nil {
		b.sessionGate = make(chan struct{}, 1)
	}
	gate := b.sessionGate
	b.mu.Unlock()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if assertion == "" {
		var err error
		assertion, err = workload.Acquire(ctx, b.acquisition, nil)
		if err != nil {
			return err
		}
	}
	b.mu.Lock()
	client := b.workload
	b.mu.Unlock()
	if client == nil {
		return connectorruntime.ErrInvalid
	}
	previous, err := client.Session()
	if err != nil {
		return err
	}
	if reuse && b.reuseAssertion(assertion) {
		return nil
	}
	session, err := client.Attach(ctx, assertion)
	if err == nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed {
			return connectorruntime.ErrExpired
		}
		b.deadline = session.ExpiresAt
		if session.AssertionExpiresAt != nil {
			b.rememberAssertion(assertion, *session.AssertionExpiresAt, session)
		} else {
			b.verification = nil
		}
		b.publishLocked()
		return nil
	}
	// a denied assertion does not stop other listeners. discard only their
	// cached admission observations so subsequent preparation checks live access.
	b.mu.Lock()
	for _, p := range b.prepared {
		p.authorizedUntil = time.Time{}
	}
	b.mu.Unlock()
	if errors.Is(err, workload.ErrSessionExpired) {
		// replacement authorizes future accepts from scratch. the old adapter and
		// its streams retain their old subject and never receive the new rights.
		if previous.Provider == controlv1.WorkloadGitHub {
			return connectorruntime.ErrExpired
		}
		b.mu.Lock()
		next := b.replacement
		b.mu.Unlock()
		if next == nil {
			next, err = workload.New(b.scope.Server, b.httpClient)
			if err != nil {
				return err
			}
			b.mu.Lock()
			if b.closed {
				b.mu.Unlock()
				return connectorruntime.ErrExpired
			}
			b.replacement = next
			b.mu.Unlock()
		}
		identity, err := next.IdentifyPolicy(ctx, b.scope.TeamID, b.scope.ProjectKey, b.scope.SourceID, b.scope.Workload, assertion)
		if err != nil {
			return err
		}
		if identity.Binding != previous.Binding {
			return connectorruntime.ErrUnauthorized
		}
		if b.replacementScope.Schema == 0 {
			b.replacementScope = b.scope
			b.replacementScope.Services = nil
			for _, name := range b.scope.Services {
				if slices.Contains(identity.Services, name) {
					b.replacementScope.Services = append(b.replacementScope.Services, name)
				}
			}
		}
		if len(b.replacementScope.Services) == 0 {
			return connectorruntime.ErrUnauthorized
		}
		session, err := exchangeConnectionWorkload(ctx, next, b.replacementScope, assertion)
		if err != nil {
			// only control-confirmed expiry permits a new retry nonce/key after
			// an exchange response was lost for longer than its original lease.
			if errors.Is(err, workload.ErrSessionExpired) {
				b.mu.Lock()
				b.replacement = nil
				b.replacementScope = connectorruntime.Context{}
				b.mu.Unlock()
			}
			return err
		}
		if session.Binding != previous.Binding {
			_ = next.Revoke(ctx)
			return connectorruntime.ErrUnauthorized
		}
		inventory, err := next.ListServices(ctx)
		if err != nil {
			return err
		}
		services := map[string]controlv1.Service{}
		metadata := meta.Metadata{Version: meta.Version, Services: map[string]meta.Service{}}
		for _, s := range inventory.Services {
			if !slices.Contains(b.scope.Services, s.Service) || string(s.Protocol) != config.Protocol(b.project.Config.Services[s.Service]) {
				continue
			}
			value, err := meta.NewEndpoint(s.Endpoint.Hostname, s.Endpoint.Hostname, string(s.Protocol), s.Endpoint.Port, s.Endpoint.Public)
			if err != nil {
				continue
			}
			services[s.Service] = controlv1.Service{Id: s.Id, Name: s.Service, TeamId: session.TeamId, Protocol: s.Protocol, Enabled: true, Endpoint: &s.Endpoint, KubernetesAuth: s.KubernetesAuth}
			metadata.Services[s.Service] = value
			if metadata.Namespace == "" {
				metadata.Namespace = value.Namespace
			}
		}
		if err := metadata.Validate(); err != nil {
			return err
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed {
			return connectorruntime.ErrExpired
		}
		b.workload = next
		b.deadline = session.ExpiresAt
		b.services, b.metadata = services, metadata.Public(false)
		b.rememberAssertion(assertion, identity.AssertionExpiresAt, session)
		b.replacement = nil
		b.replacementScope = connectorruntime.Context{}
		b.publishLocked()
		return nil
	}
	return err
}

func (b *connectorConnectionBackend) reuseAssertion(assertion string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.workload == nil {
		return false
	}
	session, err := b.workload.Session()
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(assertion))
	proof, known := b.assertions[hex.EncodeToString(digest[:])]
	if !known || !b.assertionChecks[proof.Digest].After(time.Now()) || !proof.ExpiresAt.After(time.Now()) || b.verifiedSession != session.Id || !session.LeaseExpiresAt.After(time.Now()) || !session.ExpiresAt.After(time.Now()) {
		return false
	}
	b.verification = &proof
	b.publishLocked()
	return true
}

func (b *connectorConnectionBackend) rememberAssertion(assertion string, expires time.Time, session authorityv1.WorkloadSession) {
	if assertion == "" || !expires.After(time.Now()) {
		b.verification = nil
		return
	}
	digest := sha256.Sum256([]byte(assertion))
	b.verification = &connectorruntime.AssertionVerification{Digest: hex.EncodeToString(digest[:]), Binding: session.Binding, ExpiresAt: expires}
	if b.assertions == nil || b.verifiedSession != session.Id {
		b.assertions = map[string]connectorruntime.AssertionVerification{}
		b.assertionChecks = map[string]time.Time{}
	}
	for key, proof := range b.assertions {
		if !proof.ExpiresAt.After(time.Now()) {
			delete(b.assertions, key)
			delete(b.assertionChecks, key)
		}
	}
	if len(b.assertions) >= 128 {
		for key := range b.assertions {
			delete(b.assertions, key)
			delete(b.assertionChecks, key)
			break
		}
	}
	b.assertions[b.verification.Digest] = *b.verification
	checkedUntil := time.Now().Add(30 * time.Second)
	if expires.Before(checkedUntil) {
		checkedUntil = expires
	}
	b.assertionChecks[b.verification.Digest] = checkedUntil
	b.verifiedSession = session.Id
}
func (b *connectorConnectionBackend) Verification() *connectorruntime.AssertionVerification {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.verification == nil || !b.verification.ExpiresAt.After(time.Now()) {
		return nil
	}
	v := *b.verification
	return &v
}

func (b *connectorConnectionBackend) ProjectRuntime() meta.PublicMetadata {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.metadata
}
func (b *connectorConnectionBackend) Kubeconfig() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.prepared {
		if p.ready && p.connection.Kubeconfig != "" {
			return p.connection.Kubeconfig
		}
	}
	return ""
}
func (b *connectorConnectionBackend) prepareKube(ctx context.Context, name string, p *preparedConnection) error {
	b.kubeMu.Lock()
	defer b.kubeMu.Unlock()
	source, err := kubeconfig.ResolveSource(kubeconfig.Source{TokenFile: b.kubeOptions.KubeTokenFile, ConfigFile: b.kubeOptions.KubeUserConfig, ExistingUser: b.kubeOptions.KubeUser}, p.service.KubernetesAuth)
	if err != nil {
		return err
	}
	p.kubeSource = source
	if b.scope.Workload != "" {
		if b.sessionKubePlan.Path == "" {
			b.sessionKubePlan, err = kubeconfig.PlanSession(b.directory, "session")
		}
		p.kubePlan = b.sessionKubePlan
		if b.sessionKubeResult.File != "" {
			p.kubePlan.Exclusive = false
		}
	} else {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return homeErr
		}
		p.kubePlan, err = kubeconfig.PlanLocal(home, os.Getenv("KUBECONFIG"))
	}
	if err != nil {
		return err
	}
	owner := kubeconfig.Owner{ControlURL: b.scope.Server, TeamID: b.teamID, SourceID: b.scope.SourceID, ServiceID: p.service.Id}
	p.kubeResult, err = p.kubePlan.Prepare(ctx, kubeconfig.Options{Owner: owner, ProjectLabel: b.scope.ProjectLabel, Service: name, Namespace: b.kubeOptions.Namespace, Server: "https://" + net.JoinHostPort(p.connection.Host, strconv.Itoa(p.connection.Port)), TLSServerName: p.service.Endpoint.Hostname, Helper: b.executable, Profile: filepath.Join(b.directory, "handle.json"), CredentialArgs: []string{"runtime", "connections", "kube-credential", "--handle", filepath.Join(b.directory, "handle.json"), "--service", name}})
	if err == nil {
		if b.scope.Workload != "" {
			b.sessionKubeResult = p.kubeResult
		}
		p.connection.Kubeconfig = p.kubeResult.File
		p.connection.Context = p.kubeResult.Context
	}
	return err
}

func (b *connectorConnectionBackend) Credential(ctx context.Context, name string) (credentialv1.ExecCredential, error) {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	defer finish()
	b.mu.Lock()
	p := b.prepared[name]
	if p == nil || !p.ready || p.connection.Protocol != "kubernetes" {
		b.mu.Unlock()
		return credentialv1.ExecCredential{}, kubeconfig.ErrCredential
	}
	source := p.kubeSource
	b.mu.Unlock()
	credential, err := kubeconfig.Credential(ctx, kubeconfig.Profile{Source: source}, nil)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	connection, err := b.Connect(ctx, name)
	if err != nil {
		return credentialv1.ExecCredential{}, err
	}
	if credential.Status.ExpirationTimestamp == nil || credential.Status.ExpirationTimestamp.Time.After(connection.ExpiresAt) {
		credential.Status.ExpirationTimestamp = &metav1.Time{Time: connection.ExpiresAt}
	}
	return credential, nil
}
