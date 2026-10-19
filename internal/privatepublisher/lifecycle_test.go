package privatepublisher

import (
	"context"
	"crypto/ecdsa"
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

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type lifecycleControl struct {
	publisher.ManagedHTTPControl
	mu                                  sync.Mutex
	prep                                controlv1.PrivateServiceRunPreparation
	setup                               controlv1.PrivateServiceRunSetup
	prepares, binds, heartbeats, closes int
	firstStart                          int64
	installs                            int
	replace                             bool
	revoke                              bool
	bad                                 error
	approved                            *controlv1.PrivateService
	declaration                         controlv1.PrivateServiceRunDeclaration
}

func (f *lifecycleControl) GetPublisherPrivateService(context.Context, string) (controlv1.PrivateService, error) {
	if f.approved != nil {
		return *f.approved, nil
	}
	return controlv1.PrivateService{Id: f.prep.PrivateServiceId, TeamId: f.prep.TeamId, Enabled: true, Protocol: controlv1.PrivateServiceProtocol("tcp"), TrustRevision: 1, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: f.prep.Hostname, Port: f.prep.ServicePort}}, nil
}

func (f *lifecycleControl) PreparePrivateServiceRun(_ context.Context, id, key, token string, declared ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepares++
	if len(declared) != 1 {
		f.bad = errors.New("missing exact private run declaration")
	} else {
		f.declaration = declared[0]
	}
	if id != f.prep.PrivateServiceId || !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || token != "scoped-publisher-token" {
		f.bad = errors.New("preparation used the wrong identity or service")
	}
	prep := f.prep
	prep.IdempotencyKey = key
	return prep, nil
}

func (f *lifecycleControl) StartManagedServiceRun(_ context.Context, id, run, token string, number int64) (controlv1.PrivateServiceRunSetup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds++
	if id != f.prep.PrivateServiceId || run != f.prep.PrivateRunId || token != "scoped-publisher-token" {
		f.bad = errors.New("binding used another grant")
	}
	if f.binds == 1 {
		f.firstStart = number
		return controlv1.PrivateServiceRunSetup{}, io.ErrUnexpectedEOF
	}
	if number != f.firstStart {
		f.bad = errors.New("start retry changed the prepared run")
	}
	setup := f.setup
	return setup, nil
}

func (f *lifecycleControl) HeartbeatPrivateServiceRun(_ context.Context, id, run string, token credentials.PublishRunToken) (controlv1.PrivateServiceRunState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats++
	if id != f.prep.PrivateServiceId || run != f.prep.PrivateRunId || token != "run-secret" {
		f.bad = errors.New("heartbeat used another run")
	}
	connections := append([]controlv1.ConnectionAssignment(nil), f.setup.PublisherConnections...)
	if f.replace && f.heartbeats >= 2 {
		connections[0].ConnectionAssignmentRevision++
		connections[0].PublisherConnectionId = opaqueid.PublisherConnectionPrefix + "bbbbbbbbbbbbbbbbbbbbbb"
	}
	state := controlv1.PrivateServiceRunStateState("ready")
	if f.revoke && f.heartbeats >= 2 {
		state = "closed"
	}
	return controlv1.PrivateServiceRunState{PrivateServiceId: id, PrivateRunId: run, RunNumber: f.prep.RunNumber,
		PublisherConnections: connections,
		PublisherExpiresAt:   time.Now().Add(time.Minute), State: state}, nil
}

func (f *lifecycleControl) HeartbeatPrivateServiceRunHealth(ctx context.Context, id, run string, token credentials.PublishRunToken, _ controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	return f.HeartbeatPrivateServiceRun(ctx, id, run, token)
}

func (f *lifecycleControl) ClosePrivateServiceRun(_ context.Context, id, run string, token credentials.PublishRunToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	if id != f.prep.PrivateServiceId || run != f.prep.PrivateRunId || token != "run-secret" {
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
	service := p.Preparation.PrivateServiceId
	identity := authorityv1.PublisherEnrollmentResult{
		ClientId: p.Preparation.PublisherIdentityId, GrantId: p.Preparation.PublisherGrantId,
		KeyId: p.Preparation.PublisherKeyId, TeamId: p.Preparation.TeamId,
		Kind: authorityv1.PrivateService, PrivateServiceId: &service,
	}
	f := &lifecycleControl{prep: p.Preparation, setup: controlv1.PrivateServiceRunSetup{
		PrivateServiceId: service, PrivateRunId: p.Preparation.PrivateRunId,
		RunNumber: p.Preparation.RunNumber, RunToken: "run-secret",
		PublisherConnections: []controlv1.ConnectionAssignment{bound.connections[0], bound.connections[1]},
	}}
	base := RunConfig{Control: f, Access: func(context.Context) (string, error) { return "scoped-publisher-token", nil },
		Identity: identity, PrivateServiceID: service, Target: "127.0.0.1:5432", HeartbeatInterval: 5 * time.Millisecond, Healthy: func(context.Context) bool { return true }}
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
	if f.declaration.Protocol != controlv1.PrivateServiceProtocol("tcp") || f.declaration.TrustRevision != 1 {
		t.Fatalf("run did not declare approved protocol and trust revision: %+v", f.declaration)
	}
}

func TestPrivateLifecycleRejectsUnapprovedProtocolOrTrustBeforePreparingRun(t *testing.T) {
	for _, name := range []string{"protocol", "stale-revision", "invalid-trust"} {
		t.Run(name, func(t *testing.T) {
			config, f := lifecycleFixture(t)
			approved, _ := f.GetPublisherPrivateService(t.Context(), "")
			approved.TrustRevision = 2
			f.approved = &approved
			switch name {
			case "protocol":
				f.approved.Protocol = controlv1.PrivateServiceProtocol("mysql")
			case "stale-revision":
				config.Metadata.TrustRevision = 1
			case "invalid-trust":
				trust := &controlv1.PrivateServiceTLS{Hostname: "db.fixture.test", System: true, Digest: strings.Repeat("a", 64)}
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

func (f *lifecycleControl) CreatePrivateCertificateIssuance(_ context.Context, service, run string, number int64, _ credentials.PublishRunToken, der []byte, _ string) (controlv1.PrivateCertificateIssuance, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	if err = csr.CheckSignature(); err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	now := time.Now().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	issued, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if err != nil {
		return controlv1.PrivateCertificateIssuance{}, err
	}
	value := string(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})...))
	return controlv1.PrivateCertificateIssuance{Id: "test-issuance", PrivateServiceId: service, PrivateRunId: run, RunNumber: number, CertificatePlan: *f.prep.CertificatePlan, State: controlv1.CertificateIssuanceStateWaitingForInstall, CertificatePem: &value, NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter}, nil
}
func (f *lifecycleControl) GetPrivateCertificateIssuance(context.Context, string, string, string, credentials.PublishRunToken) (controlv1.PrivateCertificateIssuance, error) {
	return controlv1.PrivateCertificateIssuance{}, errors.New("unexpected poll")
}
func (f *lifecycleControl) MarkPrivateCertificateInstalled(_ context.Context, service, run string, number int64, _ string, _ time.Time, _ credentials.PublishRunToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if service != f.prep.PrivateServiceId || run != f.prep.PrivateRunId || number != f.prep.RunNumber {
		return ErrPrivateStream
	}
	f.installs++
	return nil
}
func (f *lifecycleControl) AuthorizeServiceConnector(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: time.Now().Add(time.Minute)}, nil
}
func (f *lifecycleControl) AuthorizeServiceClientCertificate(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	return controlv1.ServiceClientCertificateDecision{}, nil
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
