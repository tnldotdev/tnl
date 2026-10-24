package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type lifecycleControl struct {
	publisher.ServiceHTTPControl
	mu                                  sync.Mutex
	prep                                controlv1.ServiceRunPreparation
	setup                               controlv1.ServiceRunSetup
	prepares, binds, heartbeats, closes int
	firstStart                          int64
	installs                            int
	replace                             bool
	revoke                              bool
	bad                                 error
	approved                            *controlv1.Service
	declaration                         controlv1.ServiceRunDeclaration
}

func (f *lifecycleControl) GetPublisherService(context.Context, string) (controlv1.Service, error) {
	if f.approved != nil {
		return *f.approved, nil
	}
	return controlv1.Service{Id: f.prep.ServiceId, TeamId: f.prep.TeamId, Enabled: true, Protocol: controlv1.ServiceProtocol("tcp"), TrustRevision: 1, Endpoint: &controlv1.ServiceEndpoint{Hostname: f.prep.Hostname, Port: f.prep.ServicePort}}, nil
}

func (f *lifecycleControl) ReadPublisherVisitorPolicy(_ context.Context, request controlv1.PublisherVisitorPolicyRequest, credential string) (controlv1.VisitorPolicyUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if request.Resource.Kind != "service" || request.Resource.Id != f.prep.ServiceId || request.RunId != f.prep.ServiceRunId || request.RunNumber != f.prep.RunNumber || credential != f.setup.RunToken {
		return controlv1.VisitorPolicyUpdate{}, errors.New("visitor policy used another service run")
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	now := time.Now()
	return controlv1.VisitorPolicyUpdate{AfterRevision: request.AfterRevision, Revisions: []int64{}, SnapshotRequired: request.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: request.Resource, Hostname: f.prep.Hostname, Port: f.prep.ServicePort, Issuer: "https://control.example.test", MetadataRevision: 1,
			VisitorPolicyRevision: 1, KeyRevision: 1, Enabled: true, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "service-fixture", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}, StreamAllocations: []controlv1.StreamCapacityAllocation{}}}, nil
}

func (f *lifecycleControl) PrepareServiceRun(_ context.Context, id, key, token string, declared controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepares++
	f.declaration = declared
	if id != f.prep.ServiceId || !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || token != "scoped-publisher-token" {
		f.bad = errors.New("preparation used the wrong identity or service")
	}
	prep := f.prep
	prep.IdempotencyKey = key
	return prep, nil
}

func (f *lifecycleControl) StartServiceRun(_ context.Context, id, run, token string, number int64) (controlv1.ServiceRunSetup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds++
	if id != f.prep.ServiceId || run != f.prep.ServiceRunId || token != "scoped-publisher-token" {
		f.bad = errors.New("binding used another grant")
	}
	if f.binds == 1 {
		f.firstStart = number
		return controlv1.ServiceRunSetup{}, io.ErrUnexpectedEOF
	}
	if number != f.firstStart {
		f.bad = errors.New("start retry changed the prepared run")
	}
	setup := f.setup
	return setup, nil
}

func (f *lifecycleControl) HeartbeatServiceRun(_ context.Context, id, run string, token credentials.ServiceRunToken) (controlv1.ServiceRunState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats++
	if id != f.prep.ServiceId || run != f.prep.ServiceRunId || token.String() != f.setup.RunToken {
		f.bad = errors.New("heartbeat used another run")
	}
	connections := append([]controlv1.ConnectionAssignment(nil), f.setup.PublisherConnections...)
	if f.replace && f.heartbeats >= 2 {
		connections[0].ConnectionAssignmentRevision++
		connections[0].PublisherConnectionId = opaqueid.PublisherConnectionPrefix + "bbbbbbbbbbbbbbbbbbbbbb"
	}
	state := controlv1.ServiceRunStateState("ready")
	if f.revoke && f.heartbeats >= 2 {
		state = "closed"
	}
	return controlv1.ServiceRunState{ServiceId: id, ServiceRunId: run, RunNumber: f.prep.RunNumber,
		PublisherConnections: connections,
		PublisherExpiresAt:   time.Now().Add(time.Minute), State: state}, nil
}

func (f *lifecycleControl) HeartbeatServiceRunHealth(ctx context.Context, id, run string, token credentials.ServiceRunToken, _ controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	return f.HeartbeatServiceRun(ctx, id, run, token)
}

func (f *lifecycleControl) CloseServiceRun(_ context.Context, id, run string, token credentials.ServiceRunToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	if id != f.prep.ServiceId || run != f.prep.ServiceRunId || token.String() != f.setup.RunToken {
		f.bad = errors.New("close used another run")
	}
	return nil
}

type heldSlot struct{ stopped chan struct{} }

func (s *heldSlot) Serve(ctx context.Context) error { <-ctx.Done(); return nil }
func (s *heldSlot) Close() error                    { close(s.stopped); return nil }

func lifecycleFixture(t *testing.T) (RunConfig, *lifecycleControl) {
	t.Helper()
	p, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	service := p.Preparation.ServiceId
	identity := authorityv1.PublisherEnrollmentResult{
		ClientId: p.Preparation.PublisherIdentityId, GrantId: p.Preparation.PublisherGrantId,
		KeyId: p.Preparation.PublisherKeyId, TeamId: p.Preparation.TeamId,
		Kind: authorityv1.Service, ServiceId: &service,
	}
	f := &lifecycleControl{prep: p.Preparation, setup: controlv1.ServiceRunSetup{
		ServiceId: service, ServiceRunId: p.Preparation.ServiceRunId,
		RunNumber: p.Preparation.RunNumber, RunToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		PublisherConnections: []controlv1.ConnectionAssignment{bound.connections[0], bound.connections[1]},
	}}
	base := RunConfig{Control: f, Access: func(context.Context) (string, error) { return "scoped-publisher-token", nil },
		Identity: identity, ServiceID: service, Target: "127.0.0.1:5432", HeartbeatInterval: 5 * time.Millisecond, Healthy: func(context.Context) bool { return true }}
	database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	base.State, err = database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	return base, f
}

func TestPrivateLifecycleKeepsTwoSlotsClosesAndRetriesExactStart(t *testing.T) {
	config, f := lifecycleFixture(t)
	var slots [2]*heldSlot
	connected := make(chan struct{}, 2)
	config.Connect = func(_ context.Context, _ *Bound, slot uint8) (SlotSession, error) {
		session := &heldSlot{stopped: make(chan struct{})}
		slots[slot] = session
		connected <- struct{}{}
		return session, nil
	}
	ready := make(chan struct{})
	config.Ready = func() error { close(ready); return nil }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("first relay was not claimed")
	}
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("second relay was not claimed")
	}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("two ready relay slots did not report readiness")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("private run did not join and close")
	}
	for _, session := range slots {
		select {
		case <-session.stopped:
		default:
			t.Fatal("relay session was not closed")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bad != nil || f.prepares != 1 || f.binds != 2 || f.heartbeats == 0 || f.closes != 1 {
		t.Fatalf("private run lifecycle: prepares=%d binds=%d heartbeats=%d closes=%d err=%v", f.prepares, f.binds, f.heartbeats, f.closes, f.bad)
	}
	if f.declaration.Protocol != controlv1.ServiceProtocol("tcp") || f.declaration.TrustRevision != 1 {
		t.Fatalf("run did not declare approved protocol and trust revision: %+v", f.declaration)
	}
}

func TestPrivateLifecycleRejectsUnapprovedProtocolOrTrustBeforePreparingRun(t *testing.T) {
	for _, name := range []string{"protocol", "stale-revision", "invalid-trust"} {
		t.Run(name, func(t *testing.T) {
			config, f := lifecycleFixture(t)
			approved, _ := f.GetPublisherService(t.Context(), "")
			approved.TrustRevision = 2
			f.approved = &approved
			switch name {
			case "protocol":
				f.approved.Protocol = controlv1.ServiceProtocol("mysql")
			case "stale-revision":
				config.Metadata.TrustRevision = 1
			case "invalid-trust":
				trust := &controlv1.ServiceTargetTLS{Hostname: "db.fixture.test", System: true, Digest: strings.Repeat("a", 64)}
				f.approved.TargetTls, config.Metadata.TargetTls = trust, trust
			}
			if err := Publish(t.Context(), config); !errors.Is(err, ErrPrivateStream) {
				t.Fatalf("unapproved declaration was published: %v", err)
			}
			if f.prepares != 0 || f.binds != 0 {
				t.Fatal("invalid metadata prepared a run or bound a private key")
			}
		})
	}
}

func TestPrivateLifecycleReplacesOnlyChangedSlotAndKeepsEndpointPlan(t *testing.T) {
	config, f := lifecycleFixture(t)
	f.replace = true
	connected := make(chan uint8, 4)
	config.Connect = func(_ context.Context, bound *Bound, slot uint8) (SlotSession, error) {
		if bound.prepared.Preparation.RunNumber != f.firstStart || bound.prepared.managedHostname != f.prep.Hostname {
			t.Error("slot replacement changed run or managed endpoint")
		}
		connected <- slot
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	counts := [2]int{}
	for range 3 {
		select {
		case slot := <-connected:
			counts[slot]++
		case err := <-done:
			t.Fatalf("run stopped on slot replacement: %v", err)
		case <-ctx.Done():
			t.Fatal("replacement never connected")
		}
	}
	if counts != [2]int{2, 1} {
		t.Fatalf("healthy slot restarted: %v", counts)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bad != nil || f.closes != 1 || f.heartbeats < 2 {
		t.Fatalf("replacement lifecycle: closes=%d heartbeats=%d err=%v", f.closes, f.heartbeats, f.bad)
	}
}

func (f *lifecycleControl) CreateServiceCertificateIssuance(_ context.Context, service, run string, number int64, _ credentials.ServiceRunToken, der []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	if err = csr.CheckSignature(); err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	now := time.Now().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	issued, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	value := string(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})...))
	return controlv1.ServiceCertificateIssuance{Id: "test-issuance", PublisherIdentityId: f.prep.PublisherIdentityId, ServiceId: service, ServiceRunId: run, RunNumber: number, CertificatePlan: *f.prep.CertificatePlan, State: controlv1.CertificateIssuanceStateWaitingForInstall, CertificatePem: &value, NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter}, nil
}
func (f *lifecycleControl) GetServiceCertificateIssuance(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error) {
	return controlv1.ServiceCertificateIssuance{}, errors.New("unexpected poll")
}
func (f *lifecycleControl) MarkServiceCertificateInstalled(_ context.Context, service, run string, number int64, _ string, _ time.Time, _ credentials.ServiceRunToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if service != f.prep.ServiceId || run != f.prep.ServiceRunId || number != f.prep.RunNumber {
		return ErrPrivateStream
	}
	f.installs++
	return nil
}

func TestPrivateLifecycleStopsWhenControlRevokesRun(t *testing.T) {
	config, f := lifecycleFixture(t)
	f.revoke = true
	config.Connect = func(_ context.Context, _ *Bound, _ uint8) (SlotSession, error) {
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := Publish(ctx, config); !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("revoked run continued serving: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bad != nil || f.closes != 1 || f.heartbeats < 2 {
		t.Fatalf("revoked run was not closed: closes=%d heartbeats=%d err=%v", f.closes, f.heartbeats, f.bad)
	}
}
