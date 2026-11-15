package daemon

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestControlProxyBackendFailureIsUnavailable(t *testing.T) {
	owner := newRuntimeTopology(t)
	ca := newIntegrationTestCA(t)
	certificate := ca.issueServer(t, "control.example.test", owner)
	serverTLS, err := staticServerTLS(certificate.certificateFile, certificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	backend, listener := serviceRuntimeListener(t, owner), serviceRuntimeListener(t, owner)
	address := backend.Addr().String()
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	serveIntegrationControlProxy(t, owner, listener, address, serverTLS)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: "control.example.test", MinVersion: tls.VersionTLS13}}
	t.Cleanup(transport.CloseIdleConnections)
	client, err := clientcontrol.New("https://"+listener.Addr().String(), &http.Client{Transport: transport, Timeout: time.Second}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discovery(t.Context()); !errors.Is(err, clientcontrol.ErrUnavailable) {
		t.Fatal("stopped backend was reported as a malformed control response", err)
	}
	if _, err := client.HeartbeatServiceRun(t.Context(), "svc_0000000000000000000000", "srun_0000000000000000000000", "fixture", controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 4}); !errors.Is(err, clientcontrol.ErrUnavailable) {
		t.Fatal("stopped backend made heartbeat terminal", err)
	}
}
