package local

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// deployment authority is covered by the PostgreSQL integration test. this
// fixture resolves the selected URL through its existing exact saved-URL grant,
// then runs the real registration worker, certificate, TLS/yamux and visitor path.
func TestDeploymentApplicationCarriesVisitorTrafficAndJoinsCleanup(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "application publication")
	}))
	defer app.Close()
	u, err := f.SavedPublicURL(t.Context(), controlv1.App, app.URL)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := owner.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{
		TeamId: u.TeamId, PublicUrlId: &u.Id, Name: "application", Kind: "installed",
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.RedeemPublisherEnrollment(t.Context(), enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	approval := controlv1.DeploymentCredential{ClientId: identity.ClientId, KeyId: identity.KeyId, GrantId: identity.GrantId, TeamId: identity.TeamId, ProjectKey: "shop", AllDeployments: true, ExpiresAt: time.Now().Add(time.Hour)}
	approval.Permissions.Publish = &controlv1.DeploymentPublishApproval{Services: new(controlv1.DeploymentCredentialServiceProtocols{"web": controlv1.ServiceProtocolHTTP})}
	token, err := (auth.DeploymentCredential{Version: 1, ControlURL: f.URL, Team: "acme", Approval: approval, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	control, err := clientcontrol.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host != f.URL {
			return original.RoundTrip(r)
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/projects/shop/deployments/production/public-urls/web" {
			selected, err := control.PublisherPublicURL(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(controlv1.DeploymentPublication{PublicUrl: selected})
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, err
		}
		return f.HTTP.Transport.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	a, _ := testAppRuntimeWorkers(t, true)
	invocation := "ivk_0123456789ABCDEFGHIJKL"
	endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": app.URL, "deployment": map[string]string{"project": "acme/shop", "name": "production", "service": "web", "credential": token}}
	var registered publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registered); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == registered.RegistrationID {
				return service.Routable
			}
		}
		return false
	})
	status, content, err := f.Visit(t.Context(), "https://"+u.CanonicalHostname)
	if err != nil || status != 200 || string(content) != "application publication" {
		t.Fatal("application publication did not carry visitor traffic", status, err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registered, nil); err != nil {
		t.Fatal(err)
	}
	if f.Runs.Load() != 1 || f.Allocations.Load() != 0 || f.Deletions.Load() != 0 {
		t.Fatal("named application changed its saved URL lifecycle")
	}
	response, err := http.Get(app.URL)
	if err != nil {
		t.Fatal("publication cleanup stopped the application", err)
	}
	_ = response.Body.Close()
}
