package local

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func applicationServiceInvocation(t *testing.T, protocol controlv1.ServiceProtocol, public bool) (*appRuntime, publisherprotocol.Endpoint, map[string]any, *publishingtest.Fixture, credentialfile.File, controlv1.Service) {
	t.Helper()
	a, endpoint, body, fixture := invocationRuntime(t)
	service := fixture.SavedService(protocol, public)
	owner, err := fixture.Owner()
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := owner.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Name: "application", Kind: "installed"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(fixture.URL, fixture.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.RedeemPublisherEnrollment(t.Context(), enrollment.EnrollmentKey, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	file, err := credentialfile.New(fixture.URL, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	file.Grants = append(file.Grants, credentialfile.Grant{ID: "pgrant_" + strings.Repeat("V", 22), Operation: controlv1.ApplicationVisit, Kind: "service", ServiceID: &service.Id})
	document, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	delete(body, "publisher_identity_id")
	body["application_credential"], body["resource_id"] = string(document), service.Id
	return a, endpoint, body, fixture, file, service
}

func TestApplicationServicePublicationUsesExistingServiceRunOperationWithoutAllocation(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, prepared := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "connector", true: "public"}[public], map[bool]string{false: "publish", true: "prepare"}[prepared]}, "/"), func(t *testing.T) {
				if !testutil.IsolatedPublishingTest(t) {
					return
				}
				a, endpoint, body, fixture, file, saved := applicationServiceInvocation(t, controlv1.ServiceProtocolHTTP, public)
				t.Setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/private/must-not-read.json")
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
				defer target.Close()
				body["target"] = target.URL
				var registration publisherprotocol.Registration
				if prepared {
					delete(body, "target")
					var assignment publisherprotocol.PublicationAssignment
					if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/prepare", body, &assignment); err != nil {
						t.Fatal(err)
					}
					if assignment.ResourceId != saved.Id || assignment.Hostname != saved.Endpoint.Hostname || public != (assignment.PublicUrl != "") {
						t.Fatal("service preparation changed reachability or fabricated an app URL", assignment)
					}
					select {
					case <-fixture.ServiceAttempts:
						t.Fatal("unbound preparation started a service run")
					default:
					}
					registration = publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: body["owner"].(string), Target: target.URL}
					if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications/register", registration, nil); err != nil {
						t.Fatal(err)
					}
				} else if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, &registration); err != nil {
					t.Fatal(err)
				}
				select {
				case attempt := <-fixture.ServiceAttempts:
					if attempt.ServiceID != saved.Id || attempt.PublisherIdentityID != file.ClientID || attempt.Declaration.Protocol != controlv1.ServiceProtocolHTTP || attempt.Declaration.TrustRevision != saved.TrustRevision {
						t.Fatal("service operation changed identity or approved metadata", attempt)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("application publication did not reach its exact service run operation", a.manager.Snapshot())
				}
				service, found := a.manager.ServiceForRegistration(registration.RegistrationID)
				if !found || !service.Registered || service.Routable || service.Ready || public != (service.PublicURL != "") {
					t.Fatal("service registration confused binding, reachability and readiness", service)
				}
				if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
					t.Fatal(err)
				}
				if fixture.Allocations.Load() != 0 || fixture.Runs.Load() != 0 || fixture.Deletions.Load() != 0 {
					t.Fatal("service publication used a public URL lifecycle")
				}
			})
		}
	}
}

func TestApplicationServicePublicationRejectsWrongOperationProtocolAndPolicy(t *testing.T) {
	for _, fault := range []string{"visit", "protocol", "resource", "policy", "limits"} {
		t.Run(fault, func(t *testing.T) {
			if !testutil.IsolatedPublishingTest(t) {
				return
			}
			protocol := controlv1.ServiceProtocolHTTP
			if fault == "protocol" {
				protocol = controlv1.Postgres
			}
			_, endpoint, body, fixture, file, _ := applicationServiceInvocation(t, protocol, false)
			switch fault {
			case "visit":
				file.Grants = file.Grants[1:]
				document, err := json.Marshal(file)
				if err != nil {
					t.Fatal(err)
				}
				body["application_credential"] = string(document)
			case "resource":
				body["resource_id"] = "svc_" + strings.Repeat("X", 22)
			case "policy":
				body["access_mode"] = "anonymous"
			case "limits":
				body["limits"] = map[string]any{"requests": 7}
			}
			var problem *publisherprotocol.ResponseError
			if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/ad-hoc/register", body, nil); !errors.As(err, &problem) || problem.Code != "runtime.credential_denied" {
				t.Fatal("service grant rejection changed its classification", err)
			}
			select {
			case <-fixture.ServiceAttempts:
				t.Fatal("rejected service publication started a run")
			default:
			}
			if fixture.Allocations.Load() != 0 || fixture.Runs.Load() != 0 || fixture.Deletions.Load() != 0 {
				t.Fatal("service grant rejection borrowed public URL authority")
			}
		})
	}
}
