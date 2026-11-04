package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectionReplacementCheckedTransitions(t *testing.T) {
	previous, client := &workload.Client{}, &workload.Client{}
	r := &workloadReplacement{previous: previous, client: client, binding: strings.Repeat("a", 64), progress: replacementAllocated{}}
	configured := connectorruntime.Context{Services: []string{"db", "removed"}} // schema is not replacement progress.
	identity := authorityv1.WorkloadIdentity{Binding: strings.Repeat("b", 64), Services: []string{"db"}, AssertionExpiresAt: time.Now().Add(time.Minute)}
	if _, err := r.selectScope(configured, identity, "first"); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("changed binding selected a scope", err)
	}
	identity.Binding = r.binding
	identity.Services = []string{"unconfigured"}
	if _, err := r.selectScope(configured, identity, "first"); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("empty intersection selected a scope", err)
	}
	if _, ok := r.progress.(replacementAllocated); !ok {
		t.Fatal("failed selection advanced the transaction")
	}
	identity.Services = []string{"db"}
	pending, err := r.selectScope(configured, identity, "first")
	if err != nil {
		t.Fatal(err)
	}
	configured.Services[0] = "changed"
	identity.Services = []string{"db", "removed", "changed"}
	retry, err := r.selectScope(configured, identity, "rotated")
	if err != nil || !reflect.DeepEqual(retry.scope.Services, []string{"db"}) || retry.assertion != "rotated" {
		t.Fatal("retry changed the fixed selection or lost its assertion", err)
	}
	session := authorityv1.WorkloadSession{Id: "wls_" + strings.Repeat("s", 22), Binding: r.binding, TeamId: "tm_" + strings.Repeat("t", 22), ExpiresAt: time.Now().Add(time.Hour), LeaseExpiresAt: time.Now().Add(time.Minute)}
	if _, err := r.confirmExchange(pending, session); !errors.Is(err, connectorruntime.ErrInvalid) || r.progress != retry {
		t.Fatal("stale response advanced another exchange", err)
	}
	exchanged, err := r.confirmExchange(retry, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.selectScope(configured, identity, "latest"); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("confirmed exchange returned to selection", err)
	}
	configuration := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"db": {Protocol: new("postgres")}}}}}
	var inventory controlv1.WorkloadServices
	if err := json.Unmarshal([]byte(`{"services":[{"id":"svc_aaaaaaaaaaaaaaaaaaaaaa","service":"db","protocol":"postgres","endpoint":{"hostname":"db.example.test","port":15443,"public":false}}]}`), &inventory); err != nil {
		t.Fatal(err)
	}
	invalid := inventory
	invalid.Services = append(slices.Clone(inventory.Services), inventory.Services[0])
	if _, err := r.validateInventory(exchanged, configuration, invalid); !errors.Is(err, connectorruntime.ErrInvalid) || r.progress != exchanged {
		t.Fatal("invalid inventory lost the confirmed session", err)
	}
	validated, err := r.validateInventory(exchanged, configuration, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.confirmAttachment(exchanged, session); !errors.Is(err, connectorruntime.ErrInvalid) || r.progress != validated {
		t.Fatal("stale attachment changed validated state", err)
	}
	b := &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{workload: client, replacement: r}}
	if err := b.promoteReplacement(r, validated, "latest", identity); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("promotion ignored its previous client", err)
	}
	b.workload = previous
	b.closed = true
	if err := b.promoteReplacement(r, validated, "latest", identity); !errors.Is(err, connectorruntime.ErrExpired) || b.workload != previous || b.replacement != r {
		t.Fatal("closed backend promoted or abandoned issued state", err)
	}
	b = &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{workload: previous, replacement: r}}
	if err := b.promoteReplacement(r, validated, "latest", identity); err != nil {
		t.Fatal(err)
	}
	if b.workload != client || b.replacement != nil || b.metadata.Services["db"].Hostname != inventory.Services[0].Endpoint.Hostname || b.deadline != session.ExpiresAt {
		t.Fatal("promotion did not install identity, deadline, and metadata together")
	}
	if err := b.promoteReplacement(r, validated, "latest", identity); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("transaction promoted twice", err)
	}
}

func TestConnectionReplacementOnlyConfirmedExpiryDiscardsRetry(t *testing.T) {
	r := &workloadReplacement{progress: &replacementExchangePending{}}
	b := &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{replacement: r}}
	for _, err := range []error{context.Canceled, connectorruntime.ErrUnauthorized, errors.New("lost response")} {
		b.discardExpiredReplacement(r, err)
		if b.replacement != r {
			t.Fatal("unconfirmed exchange lost its retry key", err)
		}
	}
	b.discardExpiredReplacement(&workloadReplacement{}, workload.ErrSessionExpired)
	if b.replacement != r {
		t.Fatal("stale expiry discarded another transaction")
	}
	b.closed = true
	b.discardExpiredReplacement(r, workload.ErrSessionExpired)
	if b.replacement != r {
		t.Fatal("shutdown lost the transaction before joining cleanup")
	}
	b.closed = false
	b.discardExpiredReplacement(r, errors.Join(workload.ErrSessionExpired, errors.New("control confirmed")))
	if b.replacement != nil {
		t.Fatal("confirmed expiry did not permit another retry key")
	}
}

func TestConnectionReplacementCannotPromoteExpiredInventory(t *testing.T) {
	for _, leaseExpired := range []bool{false, true} {
		t.Run(map[bool]string{false: "fixed window", true: "lease"}[leaseExpired], func(t *testing.T) {
			previous, client := &workload.Client{}, &workload.Client{}
			session := authorityv1.WorkloadSession{ExpiresAt: time.Now().Add(-time.Minute), LeaseExpiresAt: time.Now().Add(time.Minute)}
			if leaseExpired {
				session.ExpiresAt, session.LeaseExpiresAt = session.LeaseExpiresAt, session.ExpiresAt
			}
			validated := &replacementValidated{replacementExchanged: replacementExchanged{session: session}}
			r := &workloadReplacement{previous: previous, client: client, progress: validated}
			b := &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{workload: previous, replacement: r}}
			if err := b.promoteReplacement(r, validated, "", authorityv1.WorkloadIdentity{}); !errors.Is(err, connectorruntime.ErrExpired) || b.workload != previous || b.replacement != r {
				t.Fatal("expired inventory promoted or abandoned an issued session", err)
			}
			if _, err := r.confirmAttachment(validated, session); err != nil {
				t.Fatal("rejected promotion could not resume its confirmed session", err)
			}
		})
	}
}

func TestConnectionReplacementRequiresNonGitHubConfirmedExpiry(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider controlv1.WorkloadProvider
		status   int
	}{
		{"denied", controlv1.WorkloadVercel, http.StatusForbidden},
		{"unavailable", controlv1.WorkloadVercel, http.StatusServiceUnavailable},
		{"github expired", controlv1.WorkloadGitHub, http.StatusGone},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, team := "wls_"+strings.Repeat("s", 22), "tm_"+strings.Repeat("t", 22)
			session := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: team, ProjectKey: "project", Workload: "worker", Provider: test.provider, Binding: strings.Repeat("a", 64), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: []string{}, ExpiresAt: time.Now().Add(time.Hour), LeaseExpiresAt: time.Now().Add(time.Minute)}
			if test.provider == controlv1.WorkloadGitHub {
				session.Github = &authorityv1.WorkloadGitHubExecution{RepositoryId: "1", RepositoryOwnerId: "2", RunId: "3", RunAttempt: "4", CheckRunId: "5"}
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/workload-sessions/exchange":
					_ = json.NewEncoder(w).Encode(session)
				case "/v1/workload-sessions/" + id + "/assertions":
					w.WriteHeader(test.status)
					_ = json.NewEncoder(w).Encode(map[string]any{"status": test.status, "code": "forbidden", "detail": "fixture rejection"})
				default:
					t.Error("rejection started replacement work", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			client, err := workload.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Exchange(t.Context(), team, "project", strings.Repeat("a", 64), "worker", "first", nil); err != nil {
				t.Fatal(err)
			}
			b := &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{workload: client}, scope: connectorruntime.Context{Server: server.URL}, httpClient: server.Client()}
			if err := b.Attach(t.Context(), "rotated"); err == nil || b.replacement != nil || b.workload != client {
				t.Fatal("rejection replaced the active identity", err)
			} else if test.provider == controlv1.WorkloadGitHub && !errors.Is(err, connectorruntime.ErrExpired) {
				t.Fatal("github execution expiry changed classification", err)
			}
		})
	}
}

func TestConnectionPendingReplacementCleanupRecoverySharesBudget(t *testing.T) {
	revoked := make(chan struct{})
	b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, session authorityv1.WorkloadSession) {
		if r.Method == http.MethodDelete {
			close(revoked)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Error("unexpected active session work", r.URL.Path)
		w.WriteHeader(404)
	})
	transport := &blockedReplacementRecovery{entered: make(chan struct{}), done: make(chan struct{})}
	client, err := workload.New("https://control.example.test", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	b.replacement = &workloadReplacement{client: client, progress: &replacementExchangePending{scope: connectorruntime.Context{TeamID: "team", ProjectKey: "project", Workload: "worker", Services: []string{"db"}}, assertion: "pending"}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.Close(ctx) }()
	for _, barrier := range []<-chan struct{}{transport.entered, revoked} {
		select {
		case <-barrier:
		case <-time.After(time.Second):
			t.Fatal("pending recovery blocked active revocation or did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("incomplete pending cleanup was reported clean", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending exchange recovery outlived caller cleanup budget")
	}
	select {
	case <-transport.done:
	case <-time.After(time.Second):
		t.Fatal("pending exchange recovery did not join its canceled request")
	}
}

type blockedReplacementRecovery struct{ entered, done chan struct{} }

func (r *blockedReplacementRecovery) RoundTrip(request *http.Request) (*http.Response, error) {
	defer close(r.done)
	close(r.entered)
	<-request.Context().Done()
	return nil, request.Context().Err()
}
