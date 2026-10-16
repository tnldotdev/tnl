package privatepublisher

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type lifecycleControl struct {
	mu                                  sync.Mutex
	prep                                controlv1.PrivateServiceRunPreparation
	setup                               controlv1.PrivateServiceRunSetup
	prepares, binds, heartbeats, closes int
	firstBind                           controlv1.BindPrivateServiceRunKeyRequest
	replace                             bool
	revoke                              bool
	bad                                 error
}

func (f *lifecycleControl) PreparePrivateServiceRun(_ context.Context, id, key, token string) (controlv1.PrivateServiceRunPreparation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepares++
	if id != f.prep.PrivateServiceId || !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || token != "scoped-publisher-token" {
		f.bad = errors.New("preparation used the wrong identity or service")
	}
	prep := f.prep
	prep.IdempotencyKey = key
	return prep, nil
}

func (f *lifecycleControl) BindPrivateServiceRunKey(_ context.Context, id, run, token string, body controlv1.BindPrivateServiceRunKeyRequest) (controlv1.PrivateServiceRunSetup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds++
	if id != f.prep.PrivateServiceId || run != f.prep.PrivateRunId || token != "scoped-publisher-token" {
		f.bad = errors.New("binding used another grant")
	}
	if f.binds == 1 {
		f.firstBind = body
		return controlv1.PrivateServiceRunSetup{}, errors.New("response lost after accepting same binding")
	}
	if body != f.firstBind {
		f.bad = errors.New("binding retry changed private run key or proof")
	}
	f.setup.StreamPublicKey = body.StreamPublicKey
	setup := f.setup
	setup.StreamPublicKey = body.StreamPublicKey
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
	}
	state := controlv1.PrivateServiceRunStateState("ready")
	if f.revoke && f.heartbeats >= 2 {
		state = "closed"
	}
	return controlv1.PrivateServiceRunState{PrivateServiceId: id, PrivateRunId: run, RunNumber: f.prep.RunNumber,
		StreamPublicKey: f.setup.StreamPublicKey, PublisherConnections: connections,
		PublisherExpiresAt: time.Now().Add(time.Minute), State: state}, nil
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
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	// heartbeat must echo the key actually returned by this invocation's bind.
	// the fake reads the same request under its lock before replying.
	base := RunConfig{Control: f, Access: func(context.Context) (string, error) { return "scoped-publisher-token", nil },
		Identity: identity, SigningKey: signing, PrivateServiceID: service, Target: "127.0.0.1:5432", HeartbeatInterval: 5 * time.Millisecond}
	return base, f
}

func TestPrivateLifecycleKeepsTwoSlotsClosesAndNeverRebindsAnotherKey(t *testing.T) {
	config, f := lifecycleFixture(t)
	// setup.StreamPublicKey is set by Bind; the fake heartbeat must copy it.
	f.setup.StreamPublicKey = ""
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
}

func TestPrivateLifecycleStopsWhenHeartbeatReplacesAssignment(t *testing.T) {
	config, f := lifecycleFixture(t)
	f.replace = true
	f.setup.StreamPublicKey = ""
	config.Connect = func(_ context.Context, _ *Bound, _ uint8) (SlotSession, error) {
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err := Publish(ctx, config)
	if !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("replaced assignment was served or retried: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bad != nil || f.closes != 1 || f.heartbeats < 2 {
		t.Fatalf("stale run was not closed: closes=%d heartbeats=%d err=%v", f.closes, f.heartbeats, f.bad)
	}
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
