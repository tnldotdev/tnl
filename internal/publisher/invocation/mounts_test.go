package invocation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

type canceledMountResolver struct{}

func (canceledMountResolver) ResolveTarget(ctx context.Context, _ clientproject.Project, _ string) (string, error) {
	return "", context.Cause(ctx)
}
func (canceledMountResolver) ResolveTargetIdentity(ctx context.Context, _ clientproject.Project, _ string) (string, string, error) {
	return "", "", context.Cause(ctx)
}

func TestDiscoveredMountPreservesRequestCancellation(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{Services: config.Services{
		"web": {HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api"}}}},
		"api": {Target: &config.ServiceTarget{Type: "docker", Container: new("api"), Port: new(3000)}},
	}}}
	mounts, err := ProjectMounts(t.Context(), project, "web", nil, canceledMountResolver{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("visitor disconnected")
	cancel(cause)
	_, _, err = mounts[0].ResolveTarget(ctx)
	if !errors.Is(err, cause) {
		t.Fatalf("mount lost request cancellation: %v", err)
	}
}

func TestAppMountCapturesRegisteredTargetTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	t.Cleanup(server.Close)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	project := clientproject.Project{Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{}, HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api", StripPrefix: true}}}},
		"api": {Target: &config.ServiceTarget{Type: "app", TLS: &config.TargetTLS{CA: &ca}}},
	}}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	calls := 0
	mounts, err := ProjectMounts(ctx, project, "web", func(name string) string {
		if name != "api" {
			t.Fatalf("resolved another app: %q", name)
		}
		calls++
		return server.URL
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].Target != "" || mounts[0].ResolveTarget == nil {
		t.Fatalf("app mount lost registration-based target selection: %+v", mounts)
	}
	mount := mounts[0]
	expected, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	expected.AddCert(server.Certificate())
	if calls != 1 || mount.Options.ServerName != "127.0.0.1" || mount.Options.RootCAs == nil || !mount.Options.RootCAs.Equal(expected) {
		t.Fatalf("mount did not capture the registered listener's exact trust: calls=%d, options=%+v", calls, mount.Options)
	}
	proxy, err := publisherproxy.New(publisherproxy.Config{Target: "http://127.0.0.1:1", Hostname: "public.example", Mounts: mounts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, "GET", "https://public.example/api/health", nil)
	request.RequestURI = request.URL.RequestURI()
	request.URL.Scheme, request.URL.Host = "", ""
	request.TLS = &tls.ConnectionState{ServerName: "public.example"}
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "/health" || calls != 2 {
		t.Fatalf("registered HTTPS mount: status=%d body=%q resolutions=%d", response.Code, response.Body.String(), calls)
	}
}

func TestAppMountTrustBeforeRegistration(t *testing.T) {
	for _, hostname := range []string{"", "app.internal"} {
		t.Run(hostname, func(t *testing.T) {
			trust := &config.TargetTLS{}
			if hostname != "" {
				trust.Hostname = &hostname
			}
			project := clientproject.Project{Config: config.TNL{Services: config.Services{
				"web": {Tunnel: &config.Tunnel{}, HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api"}}}},
				"api": {Target: &config.ServiceTarget{Type: "app", TLS: trust}},
			}}}
			mounts, err := ProjectMounts(t.Context(), project, "web", func(string) string { return "" }, nil)
			if hostname == "" {
				if err == nil {
					t.Fatal("unknown app certificate identity accepted")
				}
				return
			}
			if err != nil || len(mounts) != 1 || mounts[0].Options.ServerName != hostname {
				t.Fatalf("explicit trust could not be prepared before registration: %+v, %v", mounts, err)
			}
		})
	}
}
