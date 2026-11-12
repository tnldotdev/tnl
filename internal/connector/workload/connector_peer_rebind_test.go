package workload

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorPeerRebindRetainsWorkloadSubjectAndCurrentRights(t *testing.T) {
	for _, boundary := range []string{"valid", "uncapped", "no session", "lease", "expiry", "identity expiry", "uncapped lease", "uncapped identity expiry", "service", "subject"} {
		t.Run(boundary, func(t *testing.T) {
			session := sessionFixture()
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "" {
					t.Error("workload rebind sent a control bearer")
				}
				var request controlv1.ConnectorPeerPairRebindRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				var source controlv1.VisitorTokenWorkloadSource
				if err := json.Unmarshal(request.Source, &source); err != nil || source.Credential != session.Credential {
					t.Error("workload rebind lost the current credential", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(controlv1.ConnectorPeerPairRebindState{HighWaterGeneration: 2, ReadyRelays: []controlv1.ConnectorPeerPairRelay{}})
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			body := controlv1.ConnectorPeerPairRebindRequest{Phase: "inspect", Subject: session.Subject}
			service := session.ServiceIds[0]
			client.session = cloneSession(session)
			switch boundary {
			case "uncapped":
				client.session.ExpiresAt = nil
			case "no session":
				client.session.Id = ""
			case "lease":
				client.session.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "uncapped lease":
				client.session.ExpiresAt = nil
				client.session.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "expiry":
				client.session.ExpiresAt = new(time.Now().Add(-time.Second))
			case "identity expiry":
				client.session.IdentityExpiresAt = time.Now().Add(-time.Second)
			case "uncapped identity expiry":
				client.session.ExpiresAt = nil
				client.session.IdentityExpiresAt = time.Now().Add(-time.Second)
			case "service":
				client.session.ServiceIds = nil
			case "subject":
				body.Subject.WorkloadSessionId = new("wls_aaaaaaaaaaaaaaaaaaaaaa")
			}
			state, err := client.RebindConnectorPeerPair(t.Context(), service, "cpp_bbbbbbbbbbbbbbbbbbbbbb", body)
			if boundary == "valid" || boundary == "uncapped" {
				if err != nil || calls != 1 || state.HighWaterGeneration != 2 {
					t.Fatal("valid workload rebind failed", err)
				}
			} else if err == nil || calls != 0 {
				t.Fatal("invalid workload authority reached rebind control", err)
			}
			if boundary == "lease" || boundary == "expiry" || boundary == "identity expiry" || boundary == "uncapped lease" || boundary == "uncapped identity expiry" {
				if !errors.Is(err, ErrSessionExpired) {
					t.Fatal("expired workload lost its expiry error", err)
				}
			}
		})
	}
}
