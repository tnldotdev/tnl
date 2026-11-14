package public

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceAuditBatchAPI(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	now := time.Now().UTC()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "audit_api")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	const issuer = "https://control.example.test"
	if err := d.PrepareVisitorSigningKeys(ctx, issuer, now); err != nil {
		t.Fatal(err)
	}
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	m := session.Identity.Memberships[0]
	actor := session.Identity.Identity.ID
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	relays := newAuditCompositionRelays(t, d, now)
	first := newAuditCompositionRun(t, d, pool, relays, actor, m.TeamID, m.ID, "audit-api", now)
	other := newAuditCompositionRun(t, d, pool, relays, actor, m.TeamID, m.ID, "audit-other", now)
	h, err := NewHandler(Config{ControlURL: issuer}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	control, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	permission, err := d.CreateServiceHTTPGrant(ctx, first.service.ID, actor, controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
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
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: first.service.ID, ServiceKind: "service", EventType: "http.decision", OccurredAt: now, RunID: first.run.RunID, RunNumber: first.run.RunNumber, VisitorConnectionID: visitor, SourceIP: "192.0.2.1", Outcome: "denied", Reason: "authorization"}
	body := struct {
		RunNumber int64                      `json:"run_number,string"`
		Events    []serviceaudit.Observation `json:"events"`
	}{first.run.RunNumber, []serviceaudit.Observation{o, o}}
	endpoint := server.URL + "/v1/services/" + first.service.ID + "/runs/" + first.run.RunID + "/service-observations"
	post(server.Client(), endpoint, "", body, 401)
	post(server.Client(), endpoint, other.run.Token, body, 401)
	var result controlstate.ServiceObservationResult
	if err = json.Unmarshal(post(server.Client(), endpoint, first.run.Token, body, 200), &result); err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatalf("dedup response %+v %v", result, err)
	}
	report := serviceaudit.HTTPReporter(server.Client(), func(context.Context) (serviceaudit.Destination, error) {
		return serviceaudit.Destination{URL: endpoint, Bearer: first.run.Token, RunNumber: first.run.RunNumber}, nil
	})
	if err = report(ctx, serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); err != nil {
		t.Fatal("reporter did not accept committed duplicate acknowledgement", err)
	}
	body.Events[0].RunID = other.run.RunID
	post(server.Client(), endpoint, first.run.Token, body, 403)
	post(server.Client(), endpoint, first.run.Token, map[string]any{"run_number": "1", "events": []map[string]any{{"actor_identity_id": actor}}}, 400)
	post(server.Client(), endpoint, first.run.Token, map[string]any{"run_number": 1, "events": []serviceaudit.Observation{o}}, 400)
	secret := strings.Repeat("a", 32)
	secrets, _ := serverhttp.NewBearerSecrets(secret, "")
	ingressHandler, err := controlingress.NewHandler(controlingress.Config{Store: d, ClusterSecrets: secrets, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ingressServer := httptest.NewTLSServer(ingressHandler)
	t.Cleanup(ingressServer.Close)
	ingressRun, err := opaqueid.New(opaqueid.IngressRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: "audit-ingress", IngressRunID: ingressRun, IngressPoolID: controlstate.PrimaryIngressPoolID, HTTPS: true, ProtocolVersion: 1, ConnectionCapacity: 10}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	o.EventID = serviceaudit.NewID()
	o.EventType = "connection.open"
	o.Outcome = "denied"
	o.Reason = "authorization"
	admitted, err := d.AdmitPublicServiceVisitor(ctx, lease.IngressLeaseIdentity, controlstate.PrimaryIngressPoolID, visitor,
		first.prepared.Hostname, 443, netip.MustParseAddr("192.0.2.1"), now)
	if err != nil || admitted.RunID != first.run.RunID {
		t.Fatal("audit did not bind the admitted service run", err)
	}
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
	exerciseServiceAuditQueueComposition(t, d, pool, lease, first, control, permission.Permission.VisitorToken,
		serviceaudit.HTTPReporter(ingressServer.Client(), func(context.Context) (serviceaudit.Destination, error) {
			return serviceaudit.Destination{URL: endpoint, Bearer: secret}, nil
		}))
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/teams/"+m.TeamID+"/service-audit?service_id="+first.service.ID, nil)
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
	var obsolete int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM control.public_urls`).Scan(&obsolete); err != nil || obsolete != 0 {
		t.Fatal("service audit created an obsolete publication resource", obsolete, err)
	}
}
