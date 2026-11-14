package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentOwnerFixture struct {
	backend      *connectorConnectionBackend
	credential   auth.DeploymentCredential
	denied       atomic.Bool
	selections   atomic.Int64
	blockToken   atomic.Bool
	tokenStarted chan struct{}
	tokenResume  chan struct{}
}

func newDeploymentOwnerFixture(t *testing.T, duration time.Duration, selectRun func(http.ResponseWriter, string, auth.DeploymentCredential)) *deploymentOwnerFixture {
	t.Helper()
	f := &deploymentOwnerFixture{credential: connectorDeploymentCredential(t, "https://control.example.test"), tokenStarted: make(chan struct{}, 1), tokenResume: make(chan struct{})}
	f.credential.Approval.ExpiresAt = time.Now().Add(duration)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.denied.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"title":"revoked","status":401,"code":"unauthenticated"}`))
			return
		}
		if r.URL.Path == "/v1/publisher-token" {
			if f.blockToken.Load() {
				select {
				case f.tokenStarted <- struct{}{}:
				case <-r.Context().Done():
					return
				}
				select {
				case <-f.tokenResume:
				case <-r.Context().Done():
					return
				}
			}
			// a short token makes each renewal check live authority without sleeps.
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "pta_private", "grant_id": f.credential.Approval.GrantId, "token_type": "Bearer", "expires_in": 1})
			return
		}
		f.selections.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("connector selection borrowed management authority")
		}
		prefix := "/v1/projects/shop/deployments/production/services/"
		if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, "/select") || r.URL.Query().Get("team_id") != f.credential.Approval.TeamId {
			t.Error("selection escaped its exact project and deployment", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/select")
		var body struct {
			Source controlv1.VisitorTokenRegisteredKeySource `json:"source"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Source.Kind != "registered_key" || body.Source.Credential != "pta_private" {
			t.Error("selection lost its registered-key visitor source")
		}
		if selectRun != nil {
			selectRun(w, name, f.credential)
		} else {
			_ = json.NewEncoder(w).Encode(deploymentOwnerSelection(f.credential, name))
		}
	}))
	t.Cleanup(server.Close)
	f.credential.ControlURL = server.URL
	token, err := f.credential.Encode()
	if err != nil {
		t.Fatal(err)
	}
	request := connectorruntime.DeploymentRequest{Project: "acme/shop", Name: "production", Token: token}
	project, scope, err := connectionDeployment(ContextOptions{Directory: t.TempDir(), Deployment: &request})
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := newDeploymentConnection(request, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.backend = &connectorConnectionBackend{deployment: deployment, project: project, scope: scope, parentPID: os.Getpid()}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.backend.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	return f
}

func deploymentOwnerSelection(c auth.DeploymentCredential, name string) controlv1.ServiceSelection {
	names := map[string]string{"web": "a", "db": "b", "cache": "c", "mysql": "d", "cluster": "e"}
	return controlv1.ServiceSelection{
		ServiceId: "svc_" + strings.Repeat(names[name], 22), ServiceRunId: "srun_" + strings.Repeat(names[name], 22),
		RunNumber: 1, TrustRevision: 1, Protocol: (*c.Approval.Permissions.Connect)[name],
		Endpoint:  &controlv1.ServiceEndpoint{Hostname: name + ".example.test", Port: 15443},
		ExpiresAt: time.Now().Add(time.Minute), Subject: visitorsubject.Wire(c.Subject()),
	}
}

type deploymentOwnerReady chan struct{}

func (ready deploymentOwnerReady) Write(data []byte) (int, error) {
	ready <- struct{}{}
	return len(data), nil
}

func TestDeploymentOwnerStartsWithBoundedCredentialDeadline(t *testing.T) {
	for _, duration := range []time.Duration{24 * time.Hour, 30 * 24 * time.Hour, 2 * time.Minute} {
		t.Run(duration.String(), func(t *testing.T) {
			f := newDeploymentOwnerFixture(t, duration, nil)
			b := f.backend
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			directory, err := connectorruntime.NewDirectory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ready := make(deploymentOwnerReady, 1)
			done := make(chan error, 1)
			go func() {
				done <- connectorruntime.Serve(ctx, b.scope, directory, "/fixture/tnl", b.ownerConfig(), ready)
			}()
			select {
			case <-ready:
			case err := <-done:
				t.Fatal("credential lifetime prevented owner startup", err)
			case <-time.After(5 * time.Second):
				cancel()
				<-done
				t.Fatal("owner did not publish readiness")
			}
			deadline, _ := b.AuthorizationDeadline()
			if !deadline.After(time.Now()) || deadline.After(time.Now().Add(time.Hour)) || deadline.After(f.credential.Approval.ExpiresAt) {
				t.Error("owner deadline was not finite and capped by its credential", deadline)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal("owner did not join cleanup", err)
			}
			if _, err := os.Stat(filepath.Join(directory, "handle.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("shutdown retained the local capability", err)
			}
		})
	}
}

func TestDeploymentOwnerRenewsPublishedDeadlineWithoutExtendingCredential(t *testing.T) {
	for _, duration := range []time.Duration{24 * time.Hour, 2 * time.Minute} {
		t.Run(duration.String(), func(t *testing.T) {
			f := newDeploymentOwnerFixture(t, duration, nil)
			b := f.backend
			if _, _, err := b.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			_, changed := b.AuthorizationDeadline()
			previous := time.Now().Add(time.Minute)
			b.mu.Lock()
			b.deadline = previous
			b.listeners["web"] = &ownedServiceListener{attempt: &servicePreparation{service: b.services["web"], state: &servingService{
				connection: connectorruntime.Connection{Schema: 1, Protocol: "http", Host: "127.0.0.1", Port: 15443, TransportID: "ctg_" + strings.Repeat("a", 22)},
			}}}
			b.publishLocked()
			b.mu.Unlock()
			<-changed
			before, err := b.Prepared("web")
			if err != nil || !before.ExpiresAt.Equal(previous) {
				t.Fatal("fixture did not publish its previous authorization horizon", err)
			}
			next, err := b.Renew(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			published, _ := b.AuthorizationDeadline()
			if !next.After(previous) || !next.Equal(published) || next.After(time.Now().Add(time.Hour)) || next.After(f.credential.Approval.ExpiresAt) {
				t.Fatal("renewal and native snapshots disagree on their bounded deadline", next, published)
			}
			if duration < time.Hour && !next.Equal(f.credential.Approval.ExpiresAt) {
				t.Fatal("renewal moved the fixed credential cap")
			}
			connection, err := b.Prepared("web")
			if err != nil || !connection.ExpiresAt.Equal(next) || connection.TransportID != before.TransportID {
				t.Fatal("renewal did not update the existing transport's published horizon", err)
			}
			select {
			case <-changed:
			default:
				t.Fatal("renewal did not publish its accepted horizon")
			}
			f.denied.Store(true)
			if _, err := b.Renew(t.Context()); err == nil {
				t.Fatal("revoked credential renewed owner authorization")
			}
			afterDenial, _ := b.AuthorizationDeadline()
			if !afterDenial.Equal(next) {
				t.Fatal("failed renewal extended owner authorization")
			}
			b.mu.Lock()
			b.deadline = time.Now().Add(-time.Second)
			b.mu.Unlock()
			if _, err := b.Renew(t.Context()); !errors.Is(err, connectorruntime.ErrExpired) {
				t.Fatal("renewal resurrected an expired owner horizon", err)
			}
			if _, err := b.Connect(t.Context(), "web"); !errors.Is(err, connectorruntime.ErrExpired) {
				t.Fatal("expired owner admitted new preparation", err)
			}
		})
	}
}

func TestDeploymentOwnerRejectsRenewalThatCrossesAcceptedDeadline(t *testing.T) {
	f := newDeploymentOwnerFixture(t, 24*time.Hour, nil)
	b := f.backend
	if _, _, err := b.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.blockToken.Store(true)
	// cleanup releases the fixture even if a barrier assertion fails.
	defer close(f.tokenResume)
	done := make(chan error, 1)
	go func() {
		_, err := b.Renew(t.Context())
		done <- err
	}()
	select {
	case <-f.tokenStarted:
	case err := <-done:
		t.Fatal("renewal did not enter token exchange", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	expired := time.Now().Add(-time.Second)
	_, changed := b.AuthorizationDeadline()
	b.mu.Lock()
	b.deadline = expired
	b.listeners["web"] = &ownedServiceListener{attempt: &servicePreparation{service: b.services["web"], state: &servingService{
		connection: connectorruntime.Connection{Schema: 1, Protocol: "http", Host: "127.0.0.1", Port: 15443, TransportID: "ctg_" + strings.Repeat("a", 22)},
	}}}
	b.publishLocked()
	prior := b.snapshot.Load()
	b.mu.Unlock()
	<-changed
	f.tokenResume <- struct{}{}
	if err := <-done; !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("blocked renewal resurrected an expired owner horizon", err)
	}
	deadline, _ := b.AuthorizationDeadline()
	if !deadline.Equal(expired) || b.snapshot.Load() != prior {
		t.Fatal("expired renewal replaced the prior deadline or snapshot")
	}
	if _, err := b.Prepared("web"); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("expired renewal republished a usable connection", err)
	}
	select {
	case <-changed:
		t.Fatal("expired renewal published a new authorization horizon")
	default:
	}
}

func TestDeploymentOwnerRetriesInitiallyOfflineApprovedService(t *testing.T) {
	for _, name := range []string{"web", "db", "cache", "mysql", "cluster"} {
		t.Run(name, func(t *testing.T) {
			var online, replaced, wrongProtocol atomic.Bool
			var requested atomic.Int64
			f := newDeploymentOwnerFixture(t, time.Hour, func(w http.ResponseWriter, selected string, c auth.DeploymentCredential) {
				if selected == name {
					requested.Add(1)
					if !online.Load() {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write([]byte(`{"title":"offline","status":503,"code":"unavailable"}`))
						return
					}
				}
				run := deploymentOwnerSelection(c, selected)
				if selected == name && replaced.Load() {
					run.ServiceId = "svc_" + strings.Repeat("z", 22)
				}
				if selected == name && wrongProtocol.Load() {
					run.Protocol = "tcp"
					if selected == "cache" {
						run.Protocol = "http"
					}
				}
				_ = json.NewEncoder(w).Encode(run)
			})
			b := f.backend
			if _, _, err := b.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, ok := b.ProjectRuntime().Services[name]; ok {
				t.Fatal("offline service was advertised at startup")
			}
			previous := b.ProjectRuntime()
			selectedBefore := f.selections.Load()
			if _, err := b.Prepared(name); !errors.Is(err, connectorruntime.ErrUnprepared) || f.selections.Load() != selectedBefore {
				t.Fatal("prepared read performed selection or repair", err)
			}
			online.Store(true)
			// the fixture withholds peer readiness. reaching preparation proves the
			// late selection passed the missing-inventory check, without a fake peer.
			if _, err := b.Connect(t.Context(), name); !errors.Is(err, connectorstream.ErrServiceConnection) {
				t.Fatal("late selection did not reach peer preparation", err)
			}
			if requested.Load() < 3 {
				t.Fatal("explicit retry did not reselect the current binding and run")
			}
			selected := deploymentOwnerSelection(f.credential, name)
			b.mu.Lock()
			approved, found := b.services[name]
			b.mu.Unlock()
			current := b.ProjectRuntime()
			if !found || approved.Id != selected.ServiceId || current.Services[name].Protocol != string(selected.Protocol) || current.Services[name].Hostname != selected.Endpoint.Hostname {
				t.Fatal("late selection did not install the exact approved service")
			}
			if _, ok := previous.Services[name]; ok {
				t.Fatal("late selection mutated a retained metadata snapshot")
			}
			for sibling, metadata := range previous.Services {
				if !reflect.DeepEqual(current.Services[sibling], metadata) {
					t.Fatal("late selection changed a sibling", sibling)
				}
			}
			for _, selected := range []string{"unapproved", "web/other", ""} {
				before := f.selections.Load()
				if _, err := b.Connect(t.Context(), selected); err == nil || f.selections.Load() != before {
					t.Fatal("unapproved name reached selection", selected, err)
				}
			}
			wrongProtocol.Store(true)
			if _, err := b.Connect(t.Context(), name); err == nil {
				t.Fatal("retry changed the credential's approved protocol")
			}
			wrongProtocol.Store(false)
			replaced.Store(true)
			if _, err := b.Connect(t.Context(), name); !errors.Is(err, connectorruntime.ErrUnauthorized) {
				t.Fatal("retry replaced an already selected service identity", err)
			}
			f.denied.Store(true)
			if _, err := b.Connect(t.Context(), name); err == nil {
				t.Fatal("retry bypassed current revocation")
			}
		})
	}
}
