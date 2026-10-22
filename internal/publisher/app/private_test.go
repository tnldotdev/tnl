package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

func TestPrivateHTTPRunChecksActualTargetAndFencesReplacement(t *testing.T) {
	w, _ := testWorkers(t)
	started := make(chan uint64, 4)
	var number atomic.Uint64
	number.Store(16)
	w.Configure = func(_ context.Context, _ Service) (Configuration, error) {
		return Configuration{
			RunPrivate: func(ctx context.Context, observe func(uint64, bool) error) error {
				run := number.Add(1)
				if err := observe(run, false); err != nil {
					return err
				}
				if err := observe(run, true); err != nil {
					return err
				}
				started <- run
				<-ctx.Done()
				return ctx.Err()
			}, CheckPrivate: func(ctx context.Context, service Service) Observation {
				return ProbePrivateTarget(ctx, service, targettransport.Transport{Protocol: config.ProtocolHTTP})
			},
		}, nil
	}
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer second.Close()
	var replace atomic.Bool
	id := ""
	first := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/health" || request.Header.Get(ProbeHeader) != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("private check used a public proof, app credentials or the wrong target path")
		}
		if replace.Load() {
			if err := w.Manager.Register(id, "owner", second.URL, "node"); err != nil {
				t.Error(err)
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Error("replacement private run did not start")
			}
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer first.Close()
	var err error
	id, err = w.Manager.Reserve("web", "owner", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Manager.Register(id, "owner", first.URL, "node"); err != nil {
		t.Fatal(err)
	}
	select {
	case run := <-started:
		if run != 17 {
			t.Fatalf("private run=%d", run)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("private run did not start")
	}
	snapshot, err := w.Check(t.Context(), []string{"web"})
	if err != nil || !snapshot.Services[0].Ready || snapshot.Services[0].PublicURL != "" || snapshot.Services[0].PublishRunNumber != 17 {
		t.Fatalf("private readiness: %+v: %v", snapshot.Services, err)
	}
	replace.Store(true)
	snapshot, err = w.Check(t.Context(), []string{"web"})
	if err != nil || snapshot.Services[0].Ready || snapshot.Services[0].PublishRunNumber != 18 || !snapshot.Services[0].Routable {
		t.Fatalf("stale private check crossed replacement: %+v: %v", snapshot.Services, err)
	}
	snapshot, err = w.Check(t.Context(), []string{"web"})
	if err != nil || !snapshot.Services[0].Ready || snapshot.Services[0].Observation.Status != http.StatusNoContent {
		t.Fatalf("replacement private check: %+v: %v", snapshot.Services, err)
	}
}

func TestPrivateReadinessKeepsHTTPAuthorityIndependentOfTLSTrust(t *testing.T) {
	var authority atomic.Value
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { authority.Store(r.Host); w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	transport := targettransport.Transport{Protocol: config.ProtocolHTTP, TLS: &tls.Config{RootCAs: roots, ServerName: target.Certificate().DNSNames[0]}}
	observation := ProbePrivateTarget(t.Context(), Service{Target: target.URL, ServiceProtocol: "http", Readiness: Readiness{Path: "/"}}, transport)
	if !observation.Ready || authority.Load() != strings.TrimPrefix(target.URL, "https://") {
		t.Fatal("TLS certificate identity changed HTTP target authority", observation, authority.Load())
	}
}
