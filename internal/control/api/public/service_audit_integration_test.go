package controlapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	ingressapi "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationServiceAuditBatchAPI(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	now := time.Now().UTC()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "audit_api")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	m := session.Identity.Memberships[0]
	actor := session.Identity.Identity.ID
	domains, err := d.ListTeamDomains(ctx, actor, m.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{TeamID: m.TeamID, DomainID: domains[0].ID, MembershipID: m.ID, ActingIdentityID: actor, IdempotencyKey: "audit-api", RequestDigest: sha256.Sum256([]byte("audit-api")), CanonicalHostname: "audit." + m.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var runs []string
	var tokens []credentials.PublishRunToken
	for i := range 2 {
		id, _ := opaqueid.New(opaqueid.PublishRunPrefix)
		token, tokenID, digest, err := credentials.NewPublishRunToken()
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(ctx, `INSERT INTO control.publish_runs(id,public_url_id,team_id,membership_id,acting_identity_id,publish_run_number,idempotency_key,request_digest_ciphertext,request_digest_storage_key_id,publish_run_token_id,publish_run_token_digest,policy_revision,certificate_cache_key,certificate_scope,certificate_identifiers,certificate_challenge_method,state,created_at,last_heartbeat_at,publisher_expires_at,ready_at)
			VALUES($1,$2,$3,$4,$5,$6,$1,$7,'fixture',$8,$9,1,'audit','audit',ARRAY[$10::text],'dns-01','ready',$11,$11,$12,$11)`, id, u.ID, u.TeamID, m.ID, actor, i+1, []byte{1}, tokenID.String(), digest[:], u.CanonicalHostname, now, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, id)
		tokens = append(tokens, token)
	}
	h, err := NewHandler(Config{}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	post := func(client *http.Client, endpoint, token string, body any, want int) []byte {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("status=%d want=%d body=%s", response.StatusCode, want, data)
		}
		return data
	}
	visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: u.ID, ServiceKind: "public_url", EventType: "http.decision", OccurredAt: now, RunID: runs[0], RunNumber: 1, VisitorConnectionID: visitor, SourceIP: "192.0.2.1", Outcome: "denied", Reason: "authorization"}
	body := struct {
		PublishRunNumber int64                      `json:"publish_run_number"`
		Events           []serviceaudit.Observation `json:"events"`
	}{1, []serviceaudit.Observation{o, o}}
	endpoint := server.URL + "/v1/publish-runs/" + runs[0] + "/service-observations"
	post(server.Client(), endpoint, "", body, 401)
	post(server.Client(), endpoint, tokens[1].String(), body, 401)
	var result controlstate.ServiceObservationResult
	if err = json.Unmarshal(post(server.Client(), endpoint, tokens[0].String(), body, 200), &result); err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatalf("dedup response %+v %v", result, err)
	}
	report := serviceaudit.HTTPReporter(server.Client(), func(context.Context) (serviceaudit.Destination, error) {
		return serviceaudit.Destination{URL: endpoint, Bearer: tokens[0].String(), PublishRunNumber: 1}, nil
	})
	if err = report(ctx, serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); err != nil {
		t.Fatal("reporter did not accept committed duplicate acknowledgement", err)
	}
	body.Events[0].RunID = runs[1]
	post(server.Client(), endpoint, tokens[0].String(), body, 403)
	post(server.Client(), endpoint, tokens[0].String(), map[string]any{"publish_run_number": 1, "events": []map[string]any{{"actor_identity_id": actor}}}, 400)
	secret := strings.Repeat("a", 32)
	secrets, _ := serviceapi.NewBearerSecrets(secret, "")
	ingressHandler, err := ingressapi.NewHandler(ingressapi.Config{Store: d, ClusterSecrets: secrets, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ingressServer := httptest.NewTLSServer(ingressHandler)
	t.Cleanup(ingressServer.Close)
	lease, err := d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: "audit-ingress", IngressRunID: "audit-process", ProtocolVersion: 1, ConnectionCapacity: 10,
		PrivateConnectorAddress: "127.0.0.1:9441", PrivateConnectorTLSServerName: "private.example.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	o.EventID = serviceaudit.NewID()
	o.EventType = "connection.open"
	o.Outcome = "forwarded"
	o.Reason = ""
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{o}}
	endpoint = fmt.Sprintf("%s/internal/v1/ingresses/%s/service-observations?ingress_run_id=%s&ingress_lease_revision=%d", ingressServer.URL, lease.IngressID, lease.IngressRunID, lease.IngressLeaseRevision)
	post(ingressServer.Client(), endpoint, "wrong", batch, 401)
	post(ingressServer.Client(), endpoint, secret, batch, 200)
	encoded, _ := json.Marshal(o)
	var claimedScope map[string]any
	if err = json.Unmarshal(encoded, &claimedScope); err != nil {
		t.Fatal(err)
	}
	claimedScope["team_id"] = "emitter-chosen-team"
	post(ingressServer.Client(), endpoint, secret, map[string]any{"events": []any{claimedScope}}, 400)
	post(ingressServer.Client(), endpoint+"0", secret, batch, 409)
	exerciseServiceAuditQueueComposition(t, d, pool, lease, actor, m.TeamID, m.ID, u.ID, runs[0], u.CanonicalHostname,
		serviceaudit.HTTPReporter(ingressServer.Client(), func(context.Context) (serviceaudit.Destination, error) {
			return serviceaudit.Destination{URL: endpoint, Bearer: secret}, nil
		}))
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/teams/"+u.TeamID+"/service-audit?service_id="+u.ID, nil)
	r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var page controlv1.ServiceAuditPage
	if err = json.NewDecoder(response.Body).Decode(&page); err != nil || response.StatusCode != 200 || len(page.Events) < 3 {
		t.Fatalf("safe generated audit read: %+v %d %v", page, response.StatusCode, err)
	}
}
