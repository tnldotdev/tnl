package supervisor

import (
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
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
	job := Job{Kind: KindPublicURL, Server: server.URL, ServerCAPEM: certificate}
	trusted, _, err := Clients(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.PublisherPublicURL(t.Context(), "test-token"); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatalf("job-specific control trust was not used: %v", err)
	}
	job.ServerCAPEM = nil
	untrusted, _, err := Clients(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.PublisherPublicURL(t.Context(), "test-token"); !errors.Is(err, clientcontrol.ErrUnavailable) {
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
	if err := publisherproxy.PreflightWithOptions(t.Context(), job.Target, publisherproxy.TargetOptions{RootCAs: targetRoots}); err == nil {
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
	if err := publisherproxy.PreflightWithOptions(t.Context(), job.Target, publisherproxy.TargetOptions{RootCAs: targetRoots}); err != nil {
		t.Fatalf("explicit target trust was lost: %v", err)
	}
}

func TestProtocolTargetAndTrustValidation(t *testing.T) {
	https, cert := tlsFixture(t)
	secure, _, _ := fixture(t, "secure")
	secure.Target, secure.TargetCAPEM, secure.TargetTLSName = https.URL, cert, "localhost"
	if err := validateJob(&secure); err != nil {
		t.Fatalf("configured HTTPS trust and server name were rejected: %v", err)
	}
	secure.Target = "http://127.0.0.1:3000"
	if err := validateJob(&secure); !errors.Is(err, ErrScope) {
		t.Fatalf("custom server name was allowed without HTTPS: %v", err)
	}
	for _, protocol := range []string{"http"} {
		job, _, _ := fixture(t, "one")
		job.Protocol = config.ProtocolName(protocol)
		if err := validateJob(&job); err != nil {
			t.Fatalf("valid %s target: %v", protocol, err)
		}
	}
	for _, protocol := range []config.ProtocolName{config.ProtocolPostgres, config.ProtocolMySQL, "redis", config.ProtocolTCP} {
		job, _, _ := fixture(t, "one")
		job.Protocol = protocol
		job.Target = "127.0.0.1:5432"
		if err := validateJob(&job); !errors.Is(err, ErrScope) {
			t.Fatalf("private protocol %s accepted as a public URL job: %v", protocol, err)
		}
	}
	for _, mutate := range []func(*Job){
		func(j *Job) { j.Target = "http://user:password@localhost:3000" },
		func(j *Job) { j.Target = "db.internal:5432" },
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
