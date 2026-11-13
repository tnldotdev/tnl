package invocation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestNativeIntegrationConfigCreatesUpdatesAndReloadsWithoutTarget(t *testing.T) {
	for _, purpose := range []controlv1.PublicURLPurpose{controlv1.Oauth, controlv1.Webhooks} {
		t.Run(string(purpose), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = state.Close() }()
			const server = "https://control.example"
			newID := func(prefix string) string {
				t.Helper()
				id, err := opaqueid.New(prefix)
				if err != nil {
					t.Fatal(err)
				}
				return id
			}
			prefixes := []string{}
			publicURL := controlv1.PublicURL{Id: newID(opaqueid.PublicURLPrefix), TeamId: "team", DomainId: "domain", CanonicalHostname: "integration.example", PublicUrlScope: controlv1.Shared, ServiceProtocol: controlv1.Http, Purpose: purpose, LifecycleState: controlv1.Enabled, AllowedIpPrefixes: &prefixes}
			identity := authorityv1.PublisherEnrollmentResult{ClientId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), TeamId: publicURL.TeamId, PublicUrlId: &publicURL.Id, Kind: authorityv1.SavedPublicUrl}
			enrollmentID := newID(opaqueid.PublisherEnrollmentPrefix)
			enrollmentKey := enrollmentID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			creations, updates, enrollments, redemptions := 0, 0, 0, 0
			transport := publicationHTTPTransport(func(r *http.Request) (*http.Response, error) {
				var value any
				status := http.StatusOK
				switch r.Method + " " + r.URL.Path {
				case "GET /v1/public-urls":
					page := controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{}}
					if creations != 0 {
						page.PublicUrls = append(page.PublicUrls, publicURL)
					}
					value = page
				case "POST /v1/public-urls":
					var body controlv1.CreatePublicURLRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						return nil, err
					}
					if body.Target != "" || body.Purpose != purpose || body.Ephemeral != nil && *body.Ephemeral {
						t.Errorf("integration reservation = %+v", body)
					}
					creations++
					status, value = http.StatusCreated, publicURL
				case "PATCH /v1/public-urls/" + publicURL.Id:
					var body controlv1.UpdatePublicURLRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						return nil, err
					}
					if body.Target != nil || body.AllowedIpPrefixes == nil {
						t.Errorf("integration policy update = %+v", body)
					}
					prefixes = slices.Clone(*body.AllowedIpPrefixes)
					publicURL.AllowedIpPrefixes = &prefixes
					updates++
					value = publicURL
				case "POST /v1/publisher-enrollments":
					enrollments++
					status, value = http.StatusCreated, controlv1.PublisherEnrollment{Id: enrollmentID, EnrollmentKey: enrollmentKey, ExpiresAt: time.Now().Add(time.Minute), PublicUrlId: &publicURL.Id, TeamId: publicURL.TeamId, Kind: "saved_public_url"}
				case "POST /v1/publisher-enrollments/redeem":
					redemptions++
					value = identity
				default:
					return nil, errors.New("unexpected integration setup request: " + r.Method + " " + r.URL.Path)
				}
				data, err := json.Marshal(value)
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
			})
			control, err := clientcontrol.New(server, &http.Client{Transport: transport}, "session")
			if err != nil {
				t.Fatal(err)
			}
			authority, err := clientauthority.New(server, &http.Client{Transport: transport}, "session")
			if err != nil {
				t.Fatal(err)
			}
			services := publisherServices{teamID: publicURL.TeamId, domainID: publicURL.DomainId, publicURLScope: controlv1.Shared, routes: control, authenticated: &auth.Client{ServerEndpoint: server, Control: control, Authority: authority}}
			for _, desired := range [][]string{{}, {"192.0.2.1/32"}, nil, {}} {
				services.state, err = state.Server(t.Context(), server)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := nativeIntegrationConfig(t.Context(), state, services, publicURL.CanonicalHostname, purpose, desired)
				if err != nil || cfg.Target != "" || cfg.Ephemeral || !cfg.PreserveSavedPublicURLTarget || cfg.PublisherIdentityID != identity.ClientId || cfg.AllowedIPPrefixes == nil || !slices.Equal(cfg.AllowedIPPrefixes, desired) {
					t.Fatalf("native integration config = %+v, %v", cfg, err)
				}
				if err := state.Close(); err != nil {
					t.Fatal(err)
				}
				state, err = clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
				if err != nil {
					t.Fatal(err)
				}
			}
			if creations != 1 || updates != 2 || enrollments != 1 || redemptions != 1 {
				t.Fatalf("integration setup: creates=%d updates=%d enrollments=%d redemptions=%d", creations, updates, enrollments, redemptions)
			}
			services.state, err = state.Server(t.Context(), server)
			if err != nil {
				t.Fatal(err)
			}
			publicURL.Target = "http://127.0.0.1:3000"
			_, err = nativeIntegrationConfig(t.Context(), state, services, publicURL.CanonicalHostname, purpose)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatalf("nonempty integration target loaded: %v", err)
			}
		})
	}
}
