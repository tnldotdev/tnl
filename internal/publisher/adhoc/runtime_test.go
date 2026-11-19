package adhoc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRunTargetTLSKeepsRelayAndVisitorTrustSeparate(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	prepared := make(chan testutil.PublishingRun, 1)
	fixture := publishingtest.New(t, testutil.PublishingHooks{Ready: func(_ context.Context, run testutil.PublishingRun) error {
		prepared <- run
		return nil
	}})
	// this target CA is deliberately different from the fixture's relay CA.
	// its classical TLS exchange must not weaken the visitor's PQ requirement.
	root, certificate := testutil.TLSCertificate(t, []string{"target.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	var requests atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || r.TLS.ServerName != "target.example.test" || r.TLS.Version != tls.VersionTLS13 {
			t.Error("publisher lost the captured target TLS identity")
		}
		_, _ = io.WriteString(w, "separate target TLS")
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	target.StartTLS()
	defer target.Close()
	enrollment, err := fixture.NamespaceEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(ctx, filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(ctx, fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	allocated := make(chan controlv1.Service, 1)
	done, joined := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(joined)
		done <- Run(ctx, Options{ControlURL: fixture.URL, HTTPClient: fixture.HTTP, State: profile,
			EnrollmentKey: enrollment, InvocationID: invocation, Target: target.URL,
			TargetTLS:          &controlv1.ProjectTargetTLS{Hostname: "target.example.test", CaPem: new(string(root))},
			RequirePostQuantum: true, AccessMode: controlv1.Anonymous, Limits: applicationlimits.Limits{Requests: 1},
			OnAllocated: func(service controlv1.Service) error { allocated <- service; return nil },
			Ready:       func() error { ready <- struct{}{}; return nil }})
	}()
	defer func() { cancel(); <-joined }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("target TLS publication stopped before readiness", err)
	case <-ctx.Done():
		t.Fatal("target TLS publication did not become ready", context.Cause(ctx))
	}
	service := <-allocated
	run := <-prepared
	declaration, err := targettrust.NewDeclaration("target.example.test", root)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := declaration.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if service.TargetTls == nil || service.TargetTls.System || service.TargetTls.Pem == nil ||
		*service.TargetTls.Pem != string(root) || service.TargetTls.Digest != trust.Digest ||
		!service.RequirePostQuantum || !run.Preparation.RequirePostQuantum || run.Service.Id != service.Id ||
		run.Service.TargetTls == nil || run.Service.TargetTls.Digest != trust.Digest {
		t.Fatal("saved service, target trust, and visitor PQ facts were not retained")
	}
	if service.Endpoint == nil || service.Endpoint.Port != 443 || !service.Endpoint.Public ||
		strings.Contains(service.Endpoint.Hostname, "target.example.test") {
		t.Fatal("target trust replaced the service's public endpoint")
	}
	status, body, err := fixture.Visit(ctx, "https://"+service.Endpoint.Hostname)
	if err != nil || status != http.StatusOK || string(body) != "separate target TLS" || requests.Load() != 1 {
		t.Fatal("real WSS/yamux publication did not deliver verified target bytes", status, string(body), err)
	}
	select {
	case err := <-done:
		if err != nil || ctx.Err() != nil {
			t.Fatal("target response budget did not complete normally", err, context.Cause(ctx))
		}
	case <-ctx.Done():
		t.Fatal("target TLS publication did not join after its final request", context.Cause(ctx))
	}
	if !slices.Equal(fixture.DeletedIDs(), []string{service.Id}) || fixture.Allocations.Load() != 1 || fixture.Runs.Load() != 1 {
		t.Fatal("target TLS publication did not clean up the exact service", fixture.DeletedIDs())
	}
}
