package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	publicapi "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the real CLI and public API own parsing, authentication, and wire validation.
// this recording store checks the mutation fences without PostgreSQL.
type urlUpdateStore struct {
	publicapi.ServiceStore
	publicapi.AuthorizationStore
	mu          sync.Mutex
	record      controlstate.ServiceRecord
	declaration controlstate.ProjectServiceConfiguration
	writes      int
	attempts    int
	reject      error
	pinOnRetry  bool
}

func (s *urlUpdateStore) AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error) {
	return controlstate.ControlPrincipal{IdentityID: "current-actor"}, nil
}

func (s *urlUpdateStore) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return controlstate.IdentityContext{}, nil
}

func (s *urlUpdateStore) digest() string {
	data, _ := json.Marshal(s.declaration)
	sum := sha256.Sum256(append([]byte("tnl/service-configuration/v1\x00"), data...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *urlUpdateStore) ListServices(_ context.Context, team, actor, cursor string) ([]controlstate.ServiceRecord, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if team != policyDiagnosticTeam || actor != "current-actor" || cursor != "" {
		return nil, "", controlstate.ErrServiceAccess
	}
	return []controlstate.ServiceRecord{s.record}, "", nil
}

func (s *urlUpdateStore) GetService(_ context.Context, id, actor string) (controlstate.ServiceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != s.record.ID || actor != "current-actor" {
		return controlstate.ServiceRecord{}, controlstate.ErrServiceAccess
	}
	return s.record, nil
}

func (s *urlUpdateStore) GetServiceConfiguration(_ context.Context, id, actor string) (*controlstate.ProjectServiceConfiguration, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != s.record.ID || actor != "current-actor" {
		return nil, "", controlstate.ErrServiceAccess
	}
	data, _ := json.Marshal(s.declaration)
	var result controlstate.ProjectServiceConfiguration
	_ = json.Unmarshal(data, &result)
	return &result, s.digest(), nil
}

func (s *urlUpdateStore) ConfigureService(_ context.Context, id, actor string, metadata controlstate.ServiceMetadata, declaration *controlstate.ProjectServiceConfiguration, conditions controlstate.ServiceUpdateConditions, _ time.Time) (controlstate.ServiceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if id != s.record.ID || actor != "current-actor" {
		return controlstate.ServiceRecord{}, controlstate.ErrServiceAccess
	}
	if s.reject != nil {
		return controlstate.ServiceRecord{}, s.reject
	}
	if s.pinOnRetry {
		s.pinOnRetry = false
		s.declaration.TargetTLS.HostnameFromTarget = false
		return controlstate.ServiceRecord{}, controlstate.ErrServiceConflict
	}
	if declaration == nil || conditions.ValidateConfiguration(true) != nil || conditions.ConfigurationDigest != s.digest() ||
		metadata.TrustRevision != s.record.TrustRevision || conditions.PublisherPool == nil || *conditions.PublisherPool != s.record.PublisherPool {
		return controlstate.ServiceRecord{}, controlstate.ErrServiceConflict
	}
	if metadata.Validate() != nil {
		return controlstate.ServiceRecord{}, controlstate.ErrServiceConflict
	}
	// this is a saved service, not a local project's address-free declaration.
	value := *declaration
	if value.TargetTLS != nil {
		d := value.TargetTLS
		snapshot, err := (targettrust.Declaration{Hostname: d.Hostname, CAPEM: []byte(d.CAPEM), Digest: d.Digest, HostnameFromTarget: d.HostnameFromTarget}).Snapshot()
		if err != nil || metadata.TLS == nil || snapshot.Digest != metadata.TLS.Digest {
			return controlstate.ServiceRecord{}, controlstate.ErrServiceConflict
		}
	} else if metadata.TLS != nil {
		return controlstate.ServiceRecord{}, controlstate.ErrServiceConflict
	}
	if !reflect.DeepEqual(s.record.TLS, metadata.TLS) {
		s.record.TrustRevision++
	}
	s.record.TLS = metadata.TLS
	s.record.ServiceRevision++
	s.declaration = value
	s.writes++
	return s.record, nil
}

func newURLUpdateControl(t *testing.T, public bool, trust *targettrust.Snapshot) (*urlUpdateStore, func(...string) (string, string, error)) {
	t.Helper()
	s := &urlUpdateStore{
		record: controlstate.ServiceRecord{ID: policyDiagnosticService, TeamID: policyDiagnosticTeam, Name: "update-service", Enabled: true, ServiceRevision: 1, EndpointRevision: 1,
			ServiceMetadata: controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 1, Endpoint: &controlstate.ServiceEndpoint{Hostname: "update.example.test", Port: 443, Public: public}}},
		declaration: controlstate.ProjectServiceConfiguration{Name: "update-service", Protocol: "http", Target: "127.0.0.1:3000", Public: new(public)},
	}
	if trust != nil {
		d, err := trust.Declaration()
		if err != nil {
			t.Fatal(err)
		}
		s.declaration.TargetTLS = &controlstate.ProjectTargetTLS{Hostname: d.Hostname, Digest: d.Digest, CAPEM: string(d.CAPEM), HostnameFromTarget: d.HostnameFromTarget}
		s.record.TLS = &controlstate.ServiceTargetTLS{Hostname: trust.Hostname, System: trust.System, PEM: string(trust.PEM), Digest: trust.Digest}
	}
	h, err := publicapi.NewHandler(publicapi.Config{}, publicapi.Stores{Services: s}, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, policyDiagnosticCLI(t, h.ServeHTTP)
}

func TestURLUpdateHTTPSIdentityFollowsOnlyOriginDerivedSystemTrust(t *testing.T) {
	for _, test := range []struct {
		name, explicit string
		sameOrigin     bool
		custom         bool
		plaintext      bool
		pinOnRetry     bool
		wantMismatch   bool
	}{
		{name: "origin-derived replacement"},
		{name: "plaintext to HTTPS", plaintext: true},
		{name: "same origin", sameOrigin: true},
		{name: "explicit different identity", explicit: "example.com"},
		{name: "explicit identity equal to old origin", explicit: "localhost", wantMismatch: true},
		{name: "custom roots without hostname override", custom: true},
		{name: "concurrent pin takes precedence", pinOnRetry: true, wantMismatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			roots := x509.NewCertPool()
			caFile := ""
			if test.custom {
				ca, certificate := testutil.TLSCertificate(t, []string{"localhost"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				target.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
				if !roots.AppendCertsFromPEM(ca) {
					t.Fatal("invalid fixture root")
				}
				caFile = filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(caFile, ca, 0600); err != nil {
					t.Fatal(err)
				}
			}
			target.StartTLS()
			defer target.Close()
			if !test.custom {
				roots.AddCert(target.Certificate())
			}
			oldOrigin := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
			if test.sameOrigin {
				oldOrigin = target.URL
			}
			trust, err := invocation.CaptureServiceTargetTrust(t.Context(), invocation.ServiceOptions{
				PublicOptions: invocation.PublicOptions{TargetTLSName: test.explicit, TargetCAFile: caFile}, TargetTLS: new(true),
			}, controlv1.ServiceProtocolHTTP, oldOrigin)
			if err != nil || trust == nil {
				t.Fatal("capture HTTPS trust", err)
			}
			s, invoke := newURLUpdateControl(t, true, trust)
			s.declaration.Target = strings.TrimPrefix(oldOrigin, "https://")
			if test.plaintext {
				s.declaration.TargetTLS, s.record.TLS = nil, nil
			}
			s.pinOnRetry = test.pinOnRetry
			_, stderr, err := invoke("url", "update", policyDiagnosticService, "--target", target.URL)
			if err != nil {
				t.Fatalf("CLI update failed: %v\n%s", err, stderr)
			}
			configured, _, err := s.GetServiceConfiguration(t.Context(), s.record.ID, "current-actor")
			if err != nil || configured.TargetTLS == nil || s.writes != 1 {
				t.Fatal("no acknowledged configuration mutation", err)
			}
			parsed, _ := url.Parse(target.URL)
			d := configured.TargetTLS
			automatic := test.explicit == "" && !test.custom && !test.pinOnRetry
			wantHost, wantRevision := trust.Hostname, int64(1)
			if automatic {
				wantHost = parsed.Hostname()
				if wantHost != trust.Hostname || test.plaintext {
					wantRevision++
				}
			}
			if configured.Target != parsed.Host || d.Hostname != wantHost || d.HostnameFromTarget != automatic || s.record.TrustRevision != wantRevision ||
				d.CAPEM != string(trust.PEM) || test.pinOnRetry && s.attempts != 2 {
				t.Fatal("update changed explicit trust or lost automatic provenance/revision", configured, s.record.TrustRevision, s.attempts)
			}
			snapshot, err := (targettrust.Declaration{Hostname: d.Hostname, CAPEM: []byte(d.CAPEM), Digest: d.Digest, HostnameFromTarget: d.HostnameFromTarget}).Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := snapshot.Verifier()
			if err != nil {
				t.Fatal(err)
			}
			// trust only the test CA here; retain the actual saved TLS identity.
			tlsErr := publisherproxy.PreflightWithOptions(t.Context(), target.URL, publisherproxy.TargetOptions{RootCAs: roots, ServerName: verifier.ServerName})
			if test.wantMismatch {
				var mismatch x509.HostnameError
				if !errors.As(tlsErr, &mismatch) {
					t.Fatal("explicit old identity was not pinned during real TLS", tlsErr)
				}
			} else if tlsErr != nil {
				t.Fatal("updated identity failed real TLS verification", tlsErr)
			}
		})
	}
}

func TestURLUpdateHTTPPresentsPublicAndConnectorOnlyServices(t *testing.T) {
	for _, test := range []struct {
		name     string
		public   bool
		endpoint bool
		reject   bool
	}{
		{name: "public", public: true, endpoint: true},
		{name: "connector-only", endpoint: true},
		{name: "connector-only without endpoint"},
		{name: "upstream rejection", reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			trust, err := targettrust.NewCache(nil).Capture(t.Context(), "", "old.example:443", config.TrustSource{CA: "system"})
			if err != nil {
				t.Fatal(err)
			}
			s, invoke := newURLUpdateControl(t, test.public, &trust)
			if !test.endpoint {
				s.record.Endpoint = nil
			}
			if test.reject {
				s.reject = controlstate.ErrProjectManaged
			}
			stdout, stderr, err := invoke("url", "update", policyDiagnosticService, "--target", "http://localhost:4000")
			if test.reject {
				if err == nil || s.writes != 0 || s.declaration.Target != "127.0.0.1:3000" || stdout != "" {
					t.Fatal("rejected update mutated state or reported success", s.writes, err, stdout)
				}
				return
			}
			if err != nil || stderr != "" || s.writes != 1 || s.declaration.Target != "127.0.0.1:4000" ||
				s.declaration.TargetTLS != nil || s.record.TLS != nil || s.record.TrustRevision != 2 {
				t.Fatal("valid update failed or did not clear HTTPS trust", s.declaration, err, stderr)
			}
			fields := []clioutput.Field{{Label: "service", Value: s.record.Name}, {Label: "service ID", Value: s.record.ID}}
			if test.public {
				fields = append(fields, clioutput.Field{Label: "public URL", Value: "https://update.example.test"})
			} else {
				fields = append(fields, clioutput.Field{Label: "access path", Value: "connector-only"})
			}
			fields = append(fields, clioutput.Field{Label: "target", Value: "http://127.0.0.1:4000"})
			want, err := clioutput.Render(clioutput.Frame{Command: "tnl url update", State: "updated", Footer: "restart the publisher to use the new target", Blocks: []clioutput.Block{clioutput.Fields(fields...)}})
			if err != nil || stdout != want+"\n" {
				t.Fatalf("success did not use the shared service/target presentation: %v\n%s", err, stdout)
			}
		})
	}
}
