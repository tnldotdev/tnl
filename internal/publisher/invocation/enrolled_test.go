package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnrolledServiceSelectionDoesNotTreatExactGrantsAsPrivate(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.Tcp, controlv1.Mysql, controlv1.Postgres} {
		for _, public := range []bool{false, true} {
			t.Run(string(protocol)+"/"+map[bool]string{false: "connector", true: "public"}[public], func(t *testing.T) {
				saved := enrolledServiceFixture()
				saved.Protocol, saved.Endpoint.Public = protocol, public
				address := target.URL
				if protocol != controlv1.ServiceProtocolHTTP {
					address = strings.TrimPrefix(address, "http://")
					saved.Endpoint.Port = 0
					if public {
						saved.Endpoint.Port = 23000
					}
				}
				plan, err := enrolledServicePlan(t.Context(), EnrolledOptions{PublicOptions: PublicOptions{Target: address}}, saved)
				if err != nil || string(plan.Protocol) != string(protocol) || plan.Target != address || plan.Trust != nil {
					t.Fatal("exact grant changed target selection with endpoint reachability", plan, err)
				}
			})
		}
	}
}

func enrolledServiceFixture() controlv1.Service {
	return controlv1.Service{Id: opaqueid.ServicePrefix + strings.Repeat("S", 22), Name: "web", TeamId: "team",
		Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "saved.example.test", Public: true, Port: 443}}
}

func TestEnrolledServiceSelectionRetainsSavedPolicyProtocolAndTargetTrust(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*EnrolledOptions, *controlv1.Service)
	}{
		{name: "ephemeral", modify: func(_ *EnrolledOptions, s *controlv1.Service) { s.Ephemeral = true }},
		{name: "protocol", modify: func(o *EnrolledOptions, _ *controlv1.Service) { o.Protocol = "postgres" }},
		{name: "visitor policy", modify: func(o *EnrolledOptions, _ *controlv1.Service) { o.Anonymous = true }},
		{name: "HTTP limits", modify: func(o *EnrolledOptions, _ *controlv1.Service) { o.Limits.Requests = 7 }},
		{name: "post quantum", modify: func(o *EnrolledOptions, s *controlv1.Service) {
			s.RequirePostQuantum, o.RequirePostQuantum = true, new(false)
		}},
		{name: "target trust", modify: func(o *EnrolledOptions, s *controlv1.Service) {
			declaration, err := targettrust.NewDeclaration("target.example.test", nil)
			if err != nil {
				t.Fatal(err)
			}
			trust, err := declaration.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			s.TargetTls, o.TargetTLS = publisheridentity.ServiceTargetTLS(trust), new(false)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			saved := enrolledServiceFixture()
			options := EnrolledOptions{PublicOptions: PublicOptions{Target: "http://127.0.0.1:1"}}
			test.modify(&options, &saved)
			if _, err := enrolledServicePlan(t.Context(), options, saved); err == nil {
				t.Fatal("saved grant accepted a substituted declaration")
			}
		})
	}
}

func TestPublishEnrolledRejectsMixedAuthorityBeforeOpeningState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	err := PublishEnrolled(t.Context(), EnrolledOptions{PublicOptions: PublicOptions{StateDir: root}},
		EnrolledSelection{EnrollmentKey: "-", PublisherIdentityID: "another-identity"}, nil, strings.NewReader(""))
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.PublisherSelectionInvalid {
		t.Fatal("mixed selection reached identity resolution", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mixed selection opened client state", err)
	}
}

func TestPublishEnrolledNamespaceLostReplyRetainsSharedCleanupOwner(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	fixture := publishingtest.New(t, testutil.PublishingHooks{})
	key, err := fixture.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	transport := fixture.HTTP.Transport
	var declarations []string
	fixture.HTTP.Transport = publicationHTTPTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/publisher/services" {
			return transport.RoundTrip(r)
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		declarations = append(declarations, string(data))
		r.Body = io.NopCloser(bytes.NewReader(data))
		response, err := transport.RoundTrip(r)
		if err == nil && len(declarations) == 1 {
			_ = response.Body.Close()
			cancel()
			return nil, io.ErrUnexpectedEOF
		}
		return response, err
	})
	original := http.DefaultTransport
	http.DefaultTransport = publicationHTTPTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == fixture.URL {
			return fixture.HTTP.Transport.RoundTrip(r)
		}
		return original.RoundTrip(r)
	})
	defer func() { http.DefaultTransport = original }()
	options := EnrolledOptions{PublicOptions: PublicOptions{StateDir: filepath.Join(t.TempDir(), "state"), ServerURL: fixture.URL,
		Target: target.URL, ProjectRoot: t.TempDir(), InspectionMode: config.InspectionNone}}
	err = PublishEnrolled(ctx, options, EnrolledSelection{EnrollmentKey: key}, nil, strings.NewReader(""))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrUnexpectedEOF) ||
		len(declarations) != 2 || declarations[0] != declarations[1] || fixture.Allocations.Load() != 1 ||
		fixture.Deletions.Load() != 1 || fixture.Enrollments.Load() != 1 || fixture.Runs.Load() != 0 {
		t.Fatal("namespace caller lost its original shared allocation owner", err, len(declarations), fixture.Allocations.Load(), fixture.Deletions.Load())
	}
	var request controlv1.AllocateServiceRequest
	if err := json.Unmarshal([]byte(declarations[0]), &request); err != nil {
		t.Fatal(err)
	}
	if !opaqueid.Valid(request.InvocationId, opaqueid.InvocationPrefix) || request.ExpiresAt != nil ||
		request.Configuration.Protocol == nil || *request.Configuration.Protocol != controlv1.ServiceProtocolHTTP ||
		request.Configuration.DomainId != nil || request.Configuration.Hostname != nil {
		t.Fatal("namespace caller invented expiry or allocation authority")
	}
}
