package invocation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestConfiguredPublicTrustUsesPortablePEMAndVerifiedHostname(t *testing.T) {
	ca, certificate := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ready") }))
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	target.StartTLS()
	t.Cleanup(target.Close)
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: new(config.Target(target.URL)), TLS: &config.TargetTLS{Hostname: new("target.internal"), CA: new(string(ca))}}},
	}}}
	flags := PublicOptions{Project: project, Service: "web"}
	options, err := publicTargetOptions(t.Context(), flags, target.URL)
	if err != nil || options.ServerName != "target.internal" || options.RootCAs == nil {
		t.Fatal("configured trust was lost", options, err)
	}
	if err := publisherproxy.PreflightWithOptions(t.Context(), target.URL, options); err != nil {
		t.Fatal("verified inline CA target failed", err)
	}
	options.ServerName = "wrong.internal"
	if err := publisherproxy.PreflightWithOptions(t.Context(), target.URL, options); err == nil {
		t.Fatal("target hostname mismatch was accepted")
	}
	project.Config.Services["web"].Target.TLS.CA = new("system")
	options, err = configuredTargetOptions(t.Context(), project, "web", target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherproxy.PreflightWithOptions(t.Context(), target.URL, options); err == nil {
		t.Fatal("untrusted target was accepted with system roots")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := configuredTargetOptions(ctx, flags.Project, "web", target.URL); !errors.Is(err, context.Canceled) {
		t.Fatal("capture lost cancellation", err)
	}
	// ad-hoc CLI files are a separate input boundary, not project CA selections.
	file := filepath.Join(t.TempDir(), "target.pem")
	if err := os.WriteFile(file, ca, 0600); err != nil {
		t.Fatal(err)
	}
	options, err = publicTargetOptions(t.Context(), PublicOptions{TargetCAFile: file, TargetTLSName: "target.internal"}, target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherproxy.PreflightWithOptions(t.Context(), target.URL, options); err != nil {
		t.Fatal("ad-hoc CA-file support was lost", err)
	}
}

func TestAppMountTrustCanBeCapturedBeforeItsListenerExists(t *testing.T) {
	ca, _ := testutil.TLSCertificate(t, []string{"api.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	project := clientproject.Project{Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{}, HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "api"}}}},
		"api": {Target: &config.ServiceTarget{Type: "app", TLS: &config.TargetTLS{Hostname: new("api.internal"), CA: new(string(ca))}}},
	}}}
	address := ""
	mounts, err := ProjectMounts(t.Context(), project, "web", func(string) string { return address }, nil)
	if err != nil || len(mounts) != 1 {
		t.Fatal("deferred app mount failed", mounts, err)
	}
	if mounts[0].Target != "" || mounts[0].Options.ServerName != "api.internal" || mounts[0].Options.RootCAs == nil {
		t.Fatal("deferred mount lost captured trust", mounts[0])
	}
	address = "https://127.0.0.1:8443"
	resolved, _, err := mounts[0].ResolveTarget(t.Context())
	if err != nil || resolved != address {
		t.Fatal("mount did not follow app registration", resolved, err)
	}
	project.Config.Services["api"].Target.TLS.Hostname = nil
	if _, err := ProjectMounts(t.Context(), project, "web", func(string) string { return "" }, nil); err == nil {
		t.Fatal("unknown app listener inferred a certificate hostname")
	}
}
