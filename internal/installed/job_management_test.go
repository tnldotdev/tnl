package installed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestOpenExistingDoesNotInitializeOrHideUnsafeRegistry(t *testing.T) {
	options := testOptions(t)
	if _, err := OpenExisting(t.Context(), options); !errors.Is(err, ErrRegistryMissing) {
		t.Fatalf("absent registry: %v", err)
	}
	if _, err := os.Lstat(options.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lookup created registry state: %v", err)
	}
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(clientstate.DatabasePath(options.Root)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(t.Context(), options); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("deleted registry was treated as absent: %v", err)
	}
}

func TestConnectorStopKeepsItsPortUntilServiceRemove(t *testing.T) {
	if runtime.GOOS == "darwin" {
		testutil.UseClientKeychain(t)
	}
	registry := userRegistry(t)
	job, _, _ := kindFixture(t, KindConnector)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job.StateDir = filepath.Join(parent, "client")
	database, err := clientstate.Open(t.Context(), job.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), job.Server)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := profile.ListenService(t.Context(), job.IdentityID, job.ServiceID, string(job.Protocol))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	job.Target = listener.Addr().String()
	otherID, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	other, err := profile.ListenService(t.Context(), job.IdentityID, otherID, string(job.Protocol))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	job, err = registry.InstallConnector(t.Context(), job)
	if err != nil {
		t.Fatal(err)
	}

	started, joined := make(chan struct{}), make(chan struct{})
	engine := Engine{Registry: registry, PollInterval: 5 * time.Millisecond, Connect: func(ctx context.Context, got Job, _ *clienttelemetry.Collector, ready func() error, _ func() time.Time, _ context.Context) error {
		if got.ID != job.ID || got.Target != listener.Addr().String() {
			return ErrScope
		}
		if err := ready(); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		err := listener.Close()
		close(joined)
		return err
	}}
	cancel, done := startEngine(t, engine)
	defer cancel()
	ctx, timeout := context.WithTimeout(t.Context(), 5*time.Second)
	defer timeout()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("connector did not start")
	}
	if _, err := registry.StopJob(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := registry.WaitStopped(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("connector listener was not joined")
	}
	stopped, err := registry.ResolveJob(ctx, job.ID)
	if err != nil || stopped.Enabled || stopped.IdentityID != job.IdentityID || stopped.Target != job.Target {
		t.Fatalf("stop lost the installed binding: %+v (%v)", stopped, err)
	}
	if _, found, err := profile.ServicePort(ctx, job.IdentityID, job.ServiceID); err != nil || !found {
		t.Fatalf("stop released the remembered port: %v", err)
	}
	portDatabase := clientstate.DatabasePath(database.Root())
	if err := os.Chmod(portDatabase, 0o640); err != nil {
		t.Fatal(err)
	}
	_, removeErr := registry.RemoveJob(ctx, job.ID)
	if err := os.Chmod(portDatabase, 0o600); err != nil {
		t.Fatal(err)
	}
	if removeErr == nil {
		t.Fatal("remove accepted unsafe connector state")
	}
	if _, err := registry.ResolveJob(ctx, job.ID); err != nil {
		t.Fatalf("failed release removed the job before retry: %v", err)
	}
	if _, err := registry.RemoveJob(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ResolveJob(ctx, job.ID); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("removed job was retained: %v", err)
	}
	if _, found, err := profile.ServicePort(ctx, job.IdentityID, job.ServiceID); err != nil || found {
		t.Fatalf("remove did not release the remembered port: %v", err)
	}
	if _, found, err := profile.ServicePort(ctx, job.IdentityID, otherID); err != nil || !found {
		t.Fatalf("remove released another service's port: %v", err)
	}
	joinEngine(t, cancel, done)
}
