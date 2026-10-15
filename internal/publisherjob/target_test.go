package publisherjob

import (
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func tlsFixture(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"unauthenticated"}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return server, certificate
}

func TestControlAndTargetTrustAreIndependentPerJob(t *testing.T) {
	server, certificate := tlsFixture(t)
	job := Job{Server: server.URL, ServerCAPEM: certificate}
	trusted, _, err := Clients(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.PublisherPublicURL(t.Context(), "test-token"); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatalf("job-specific control trust was not used: %v", err)
	}
	job.ServerCAPEM = nil
	untrusted, _, err := Clients(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.PublisherPublicURL(t.Context(), "test-token"); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatalf("control roots leaked into another job: %v", err)
	}

	job.Target, job.Protocol, job.ServerCAPEM = server.URL, "http", certificate
	if err := validateTarget(&job); err != nil {
		t.Fatal(err)
	}
	targetRoots, err := trustRoots(job.TargetCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxy.PreflightWithOptions(t.Context(), job.Target, localproxy.TargetOptions{RootCAs: targetRoots}); err == nil {
		t.Fatal("control roots leaked into target trust")
	}
	job.TargetCAPEM = certificate
	if err := validateTarget(&job); err != nil {
		t.Fatal(err)
	}
	targetRoots, err = trustRoots(job.TargetCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxy.PreflightWithOptions(t.Context(), job.Target, localproxy.TargetOptions{RootCAs: targetRoots}); err != nil {
		t.Fatalf("explicit target trust was lost: %v", err)
	}
}

func TestProtocolTargetAndTrustValidation(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "mysql", "redis", "ssh"} {
		job, _, _ := fixture(t, "one")
		job.Protocol = controlv1.PublicURLServiceProtocol(protocol)
		if protocol != "http" {
			job.Target = "127.0.0.1:5432"
			job.TargetTLS = true
			job.TargetTLSName = "target.internal"
		}
		if err := validateJob(&job); err != nil {
			t.Fatalf("valid %s target: %v", protocol, err)
		}
	}
	for _, mutate := range []func(*Job){
		func(j *Job) { j.Target = "http://user:password@localhost:3000" },
		func(j *Job) { j.TargetTLS = true },
		func(j *Job) { j.TargetCAPEM = []byte("not a certificate") },
		func(j *Job) { j.ServerCAPEM = []byte("not a certificate") },
		func(j *Job) { j.Protocol = "postgres"; j.Target = "postgres://user:password@localhost/db" },
		func(j *Job) { j.Protocol = "redis"; j.Target = "localhost:6379"; j.TargetTLSName = "target.internal" },
	} {
		job, _, _ := fixture(t, "one")
		mutate(&job)
		if err := validateJob(&job); !errors.Is(err, ErrScope) {
			t.Fatalf("unsafe private target accepted: %v", err)
		}
	}
}
