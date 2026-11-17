package stream

import (
	"context"
	"crypto/tls"
	"database/sql"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorFailedClaimRefundsApplicationBudget(t *testing.T) {
	const hostname = "service.example.test"
	certificate := visitorfixture.Certificate(t, hostname)
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1), Total: new(1),
		Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"}})
	if err != nil {
		t.Fatal(err)
	}
	var committed, applications atomic.Int32
	transport := &http.Transport{MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			incoming, visitor := net.Pipe()
			stream := Stream{Protocol: config.ProtocolHTTP, Hostname: hostname, HTTPRequests: budget,
				TLS: &tls.Config{Certificates: []tls.Certificate{certificate}},
				Visitor: ConnectorVisitor{Admission: &AdmissionFixture{Check: func(context.Context) (Decision, error) {
					return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				}}},
				PrepareRequest: func(r *http.Request) (func(context.Context) error, error) {
					if r.URL.Path != "/callback" {
						return nil, nil
					}
					return func(context.Context) error { committed.Add(1); return sql.ErrNoRows }, nil
				},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					applications.Add(1)
					w.WriteHeader(http.StatusNoContent)
				})}
			done := make(chan error, 1)
			go func() { defer incoming.Close(); done <- stream.Forward(t.Context(), incoming) }()
			t.Cleanup(func() {
				_ = visitor.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("connector HTTP stream did not join")
				}
			})
			return visitor, nil
		}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	visit := func(path string) int {
		t.Helper()
		response, err := client.Get("https://" + hostname + path)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(readErr, closeErr)
		}
		return response.StatusCode
	}
	if got := visit("/callback"); got != http.StatusServiceUnavailable || committed.Load() != 1 || applications.Load() != 0 {
		t.Fatal("claim rejection fixture failed", got, committed.Load(), applications.Load())
	}
	select {
	case <-budget.Completed():
		t.Error("rejected claim completed the run's request budget without an app request")
	default:
	}
	if got := visit("/ordinary"); got != http.StatusNoContent || applications.Load() != 1 {
		t.Fatal("failed claim spent total, concurrency, or rate budget", got, applications.Load())
	}
	select {
	case <-budget.Completed():
	default:
		t.Fatal("forwarded application request did not complete its lifetime budget")
	}
}
