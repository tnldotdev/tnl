package publisherjob

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestPrivatePublisherCannotUseAPublicURLGrant(t *testing.T) {
	r := testRegistry(t)
	job, identity, key := fixture(t, "private")
	service, err := opaqueid.New(opaqueid.PrivateServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	job.Kind, job.PrivateServiceID, job.PublicURLID = KindPrivateService, service, ""
	job.TrustRevision = 1
	job.Protocol, job.Target = "tcp", "127.0.0.1:22"
	if err := r.Install(t.Context(), job, identity, key); !errors.Is(err, ErrScope) {
		t.Fatalf("public grant installed for private service: %v", err)
	}
	identity.Kind, identity.PrivateServiceId, identity.PublicUrlId = authorityv1.PrivateService, &service, nil
	if err := r.Install(t.Context(), job, identity, key); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err := r.signingIdentity(t.Context(), job)
	if err != nil || loaded.PrivateServiceId == nil || *loaded.PrivateServiceId != service {
		t.Fatalf("private grant changed: %+v, %v", loaded, err)
	}
	job.PrivateServiceID, _ = opaqueid.New(opaqueid.PrivateServicePrefix)
	if _, _, _, err := r.signingIdentity(t.Context(), job); !errors.Is(err, ErrScope) {
		t.Fatalf("private key crossed service IDs: %v", err)
	}
}

func TestConnectorIsUserOnlyAndJoinsBeforeRemoval(t *testing.T) {
	options := testOptions(t)
	options.User = true
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	service, err := opaqueid.New(opaqueid.PrivateServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	job := Job{Kind: KindConnector, ID: "connect-test", Name: "database", Server: "https://control.example", PrivateServiceID: service,
		StateDir: t.TempDir(), Protocol: "postgres", Target: "127.0.0.1:15432", TrustRevision: 1}
	job.IdentityID, err = opaqueid.New(opaqueid.IdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InstallConnector(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	started, joined := make(chan struct{}), make(chan struct{})
	engine := Engine{Registry: r, PollInterval: 5 * time.Millisecond, Connect: func(ctx context.Context, got Job, ready func() error) error {
		if got.PrivateServiceID != service || got.IdentityID != job.IdentityID || got.Target != job.Target {
			return ErrScope
		}
		if err := ready(); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		close(joined)
		return nil
	}}
	cancel, done := startEngine(t, engine)
	defer cancel()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("connector did not start")
	}
	if err := r.Remove(t.Context(), job.ID); !errors.Is(err, ErrScope) {
		t.Fatalf("running connector removed: %v", err)
	}
	if err := r.Stop(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	wait, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if err := r.WaitStopped(wait, job.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("connector was not joined")
	}
	if err := r.Remove(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	joinEngine(t, cancel, done)
	system := testRegistry(t)
	if err := system.InstallConnector(t.Context(), job); !errors.Is(err, ErrScope) {
		t.Fatalf("system registry accepted connector: %v", err)
	}
}
