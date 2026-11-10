package workload

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func applicationSessionFixture() authorityv1.WorkloadSession {
	s := sessionFixture(controlv1.WorkloadGitHub)
	s.Application.Grants[0].ExpiresAt = new(time.Now().Add(time.Hour))
	s.Application.Grants = append(s.Application.Grants,
		controlv1.PublisherGrant{Id: "pgrant_" + strings.Repeat("P", 22), Kind: controlv1.PublisherGrantKindService, Operation: controlv1.ApplicationPublish, ServiceId: new(*s.Application.Grants[0].ServiceId), CreatedAt: s.Application.Grants[0].CreatedAt},
		controlv1.PublisherGrant{Id: "pgrant_" + strings.Repeat("N", 22), Kind: controlv1.PublisherGrantKindNamespace, Operation: controlv1.ApplicationAllocate, DomainId: new("dom_" + strings.Repeat("N", 22)), Namespace: new("member.example.test"), CreatedAt: s.Application.Grants[0].CreatedAt},
	)
	return s
}

func TestApplicationSessionResponsesCannotReplaceOrWidenAuthority(t *testing.T) {
	for _, operation := range []string{"initial", "exchange retry", "renew", "attach"} {
		for _, test := range []struct {
			name            string
			change          func(*authorityv1.WorkloadSession)
			initial, update bool
		}{
			{"unchanged", func(*authorityv1.WorkloadSession) {}, true, true},
			{"empty after narrowing", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants = []controlv1.PublisherGrant{}
				s.ServiceIds = []string{}
			}, true, true},
			{"missing application", func(s *authorityv1.WorkloadSession) { s.Application = controlv1.RegisteredApplication{} }, false, false},
			{"invalid client", func(s *authorityv1.WorkloadSession) { s.Application.ClientId = "pub_invalid" }, false, false},
			{"different client", func(s *authorityv1.WorkloadSession) { s.Application.ClientId = "pub_" + strings.Repeat("B", 22) }, true, false},
			{"different key", func(s *authorityv1.WorkloadSession) { s.Application.KeyId = "pkey_" + strings.Repeat("B", 22) }, true, false},
			{"different team", func(s *authorityv1.WorkloadSession) { s.Application.TeamId = "another" }, false, false},
			{"different name", func(s *authorityv1.WorkloadSession) { s.Application.Name = "another" }, false, false},
			{"invalid ownership", func(s *authorityv1.WorkloadSession) { s.Application.Ownership = "other" }, false, false},
			{"changed ownership", func(s *authorityv1.WorkloadSession) { s.Application.Ownership = controlv1.RegisteredApplicationTeam }, true, false},
			{"duplicate grant", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants = append(s.Application.Grants, s.Application.Grants[0])
			}, false, false},
			{"revoked grant", func(s *authorityv1.WorkloadSession) { s.Application.Grants[0].RevokedAt = new(time.Now()) }, false, false},
			{"cross-team grant", func(s *authorityv1.WorkloadSession) { s.Application.Grants[0].TeamId = new("another") }, false, false},
			{"mixed resource", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[0].PublicUrlId = new("url_" + strings.Repeat("U", 22))
			}, false, false},
			{"allocation operation", func(s *authorityv1.WorkloadSession) { s.Application.Grants[2].Operation = controlv1.ApplicationPublish }, false, false},
			{"unlisted visit authority", func(s *authorityv1.WorkloadSession) { s.Application.Grants = s.Application.Grants[1:] }, false, false},
			{"expired grant", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[0].ExpiresAt = new(time.Now().Add(-time.Second))
			}, false, false},
			{"shortened grant", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[0].ExpiresAt = new(s.Application.Grants[0].ExpiresAt.Add(-time.Minute))
			}, true, true},
			{"extended grant", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[0].ExpiresAt = new(s.Application.Grants[0].ExpiresAt.Add(time.Minute))
			}, true, false},
			{"removed grant expiry", func(s *authorityv1.WorkloadSession) { s.Application.Grants[0].ExpiresAt = nil }, true, false},
			{"new grant ID", func(s *authorityv1.WorkloadSession) { s.Application.Grants[1].Id = "pgrant_" + strings.Repeat("B", 22) }, true, false},
			{"new resource", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[1].ServiceId = new("svc_" + strings.Repeat("B", 22))
			}, true, false},
			{"new operation", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[1].Operation = controlv1.ApplicationVisit
				s.Application.Grants = s.Application.Grants[1:]
			}, true, false},
			{"changed creation time", func(s *authorityv1.WorkloadSession) {
				s.Application.Grants[1].CreatedAt = s.Application.Grants[1].CreatedAt.Add(time.Second)
			}, true, false},
			{"future creation time", func(s *authorityv1.WorkloadSession) { s.Application.Grants[1].CreatedAt = time.Now().Add(time.Hour) }, false, false},
			{"grant overflow", func(s *authorityv1.WorkloadSession) { s.Application.Grants = make([]controlv1.PublisherGrant, 65) }, false, false},
		} {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				original := applicationSessionFixture()
				next := cloneSession(original)
				if operation == "renew" {
					next.RenewalSequence++
				}
				test.change(&next)
				calls := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					value := original
					if operation == "initial" || calls > 0 {
						value = next
					}
					calls++
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(value)
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				exchange := func() (authorityv1.WorkloadSession, error) {
					return client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil)
				}
				var before authorityv1.WorkloadSession
				if operation != "initial" {
					if _, err := exchange(); err != nil {
						t.Fatal(err)
					}
					before, _ = client.Session()
				}
				var result authorityv1.WorkloadSession
				switch operation {
				case "initial", "exchange retry":
					result, err = exchange()
				case "renew":
					result, err = client.Renew(t.Context())
				case "attach":
					result, err = client.Attach(t.Context(), "fresh assertion")
				}
				accept := test.update
				if operation == "initial" {
					accept = test.initial
				}
				if (err == nil) != accept {
					t.Fatal("wrong application response acceptance", err)
				}
				if accept {
					return
				}
				if result.Id != "" {
					t.Fatal("invalid response returned usable authority")
				}
				retained, sessionErr := client.Session()
				if operation == "initial" {
					if !errors.Is(sessionErr, ErrNoSession) {
						t.Fatal("invalid response installed a session", sessionErr)
					}
				} else if sessionErr != nil || !reflect.DeepEqual(retained, before) {
					t.Fatal("failed update replaced confirmed authority", sessionErr)
				}
			})
		}
	}
}

func TestPrepareApplicationUsesRetainedKeyAndIndependentGrantDocuments(t *testing.T) {
	original := applicationSessionFixture()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(original)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PrepareApplication(); !errors.Is(err, ErrNoSession) {
		t.Fatal("prepared authority before exchange", err)
	}
	response, err := client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := client.PrepareApplication()
	if err != nil {
		t.Fatal(err)
	}
	key, err := prepared.Validate()
	if err != nil || !client.PublicKey().Equal(key.Public()) {
		t.Fatal("preparation replaced the exchanged signing key", err)
	}
	proof, err := publisherproof.Sign(prepared.ClientID, prepared.KeyID, prepared.Grants[1].ID, server.URL, key, time.Now())
	if err != nil || proof == "" {
		t.Fatal("prepared authority could not sign publisher proof", err)
	}
	if prepared.ControlURL != server.URL || len(prepared.Grants) != 3 || !prepared.Grants[0].ExpiresAt.Equal(*original.Application.Grants[0].ExpiresAt) || !prepared.Grants[0].ExpiresAt.After(original.LeaseExpiresAt) {
		t.Fatal("prepared document lost its captured identity or grant lifetime")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, prepared), prepared.PrivateKey) {
			t.Fatal("prepared key appeared in diagnostics")
		}
	}
	before, _ := client.Session()
	snapshot, _ := client.Session()
	*snapshot.Application.Grants[0].ServiceId = "snapshot mutation"
	*snapshot.Application.Grants[0].ExpiresAt = time.Time{}
	*snapshot.Application.Grants[2].DomainId = "snapshot mutation"
	*snapshot.Application.Grants[2].Namespace = "snapshot mutation"
	*response.Application.Grants[0].ServiceId = "response mutation"
	*response.Application.Grants[0].ExpiresAt = time.Time{}
	*prepared.Grants[0].ServiceID = "document mutation"
	*prepared.Grants[0].ExpiresAt = time.Time{}
	*prepared.Grants[2].DomainID = "document mutation"
	*prepared.Grants[2].Namespace = "document mutation"
	if retained, _ := client.Session(); !reflect.DeepEqual(retained, before) {
		t.Fatal("returned authority mutated retained session")
	}
	other, err := client.PrepareApplication()
	if err != nil {
		t.Fatal("independent document was mutated", err)
	}
	*other.Grants[1].ServiceID = "another mutation"
	if retained, _ := client.Session(); !reflect.DeepEqual(retained, before) {
		t.Fatal("repeated preparation aliased confirmed authority")
	}
	for _, name := range []string{"lease", "proof", "hard deadline", "no grants"} {
		t.Run(name, func(t *testing.T) {
			client.session = cloneSession(before)
			want := ErrSessionExpired
			switch name {
			case "lease":
				client.session.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "proof":
				client.session.IdentityExpiresAt = time.Now().Add(-time.Second)
			case "hard deadline":
				client.session.ExpiresAt = new(time.Now().Add(-time.Second))
			case "no grants":
				client.session.Application.Grants = nil
				want = credentialfile.ErrInvalid
			}
			if _, err := client.PrepareApplication(); !errors.Is(err, want) {
				t.Fatal("unavailable authority became a prepared credential", err)
			}
		})
	}
}
