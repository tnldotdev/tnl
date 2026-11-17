package invocation

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationRetriesDoNotStartForegroundShutdown(t *testing.T) {
	f := newServiceSetupFixture(t, "oauth.member.example")
	f.saved.EndpointRevision = 1
	revisionChanged := errors.New("integration revision changed after preparation")
	var parentCalls, cleanupQueries atomic.Int32
	parent, end := context.WithTimeout(t.Context(), 15*time.Second)
	defer end()
	parent = observability.WithShutdownDeadline(parent, func(until time.Time) time.Time { parentCalls.Add(1); return until })
	publication, deadline, fence, finish := publicationShutdown(parent)
	defer finish()
	attachment, stopAttachment := context.WithCancel(publication)
	defer stopAttachment()
	closed, reports, prepared, cleared := 0, 0, 0, 0
	var last publisherservice.RunConfig
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/services/"+f.saved.Id+"/runs" {
			f.runs++
			run := controlv1.ServiceRunPreparation{ServiceId: f.saved.Id, TeamId: f.saved.TeamId, DomainId: *f.saved.DomainId,
				ServiceRunId: serviceTestID(t, opaqueid.ServiceRunPrefix), RunNumber: int64(f.runs), RunToken: "integration-run-token",
				IdempotencyKey: r.Header.Get("Idempotency-Key"), PublisherIdentityId: f.identity.ClientId,
				PublisherGrantId: f.identity.GrantId, PublisherKeyId: f.identity.KeyId, Hostname: f.saved.Endpoint.Hostname,
				ExpiresAt: time.Now().Add(time.Minute),
				CertificatePlan: &controlv1.CertificatePlan{CacheKey: "integration-budget", Scope: f.saved.Endpoint.Hostname,
					Identifiers: []string{f.saved.Endpoint.Hostname}, ChallengeMethod: controlv1.Dns01},
				Traffic: controlv1.TrafficLimits{Connections: 32, Rate: 20, RatePerNs: int64(time.Second), Burst: 40,
					UploadBytes: 8 << 20, DownloadBytes: 16 << 20}}
			return serviceTestResponse(r, 200, run), true
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/services/"+f.saved.Id+"/runs/") {
			if r.Header.Get("Authorization") != "Bearer integration-run-token" {
				t.Error("cleanup lost its exact service run credential")
			}
			closed++
			return serviceTestResponse(r, 200, struct{}{}), true
		}
		return nil, false
	}
	worker := integrations.Publisher{State: f.state, Store: f.services.state,
		Server: f.services.authenticated.ServerEndpoint, Hostname: f.saved.Endpoint.Hostname,
		Prepare: func(ctx context.Context) (integrations.Snapshot, error) {
			cfg, saved, err := nativeIntegrationConfig(ctx, f.services, f.saved.Endpoint.Hostname, targetsyntax.OAuthIntegration, nil,
				integrationShutdown{deadline: deadline, fence: fence})
			if err != nil {
				return integrations.Snapshot{}, err
			}
			original := cfg.ShutdownDeadline
			cfg.ShutdownDeadline = func() time.Time { cleanupQueries.Add(1); return original() }
			cfg.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error { prepared++; return revisionChanged }
			last = cfg
			return integrations.Snapshot{Config: cfg, Service: saved, Readiness: func(ctx context.Context, ready bool) error {
				if ready {
					t.Error("retired preparation became ready")
				}
				if parentCalls.Load() != 0 || publication.Err() != nil {
					t.Error("routine readiness cleanup started foreground shutdown")
				}
				cleared++
				return nil
			}}, nil
		},
		Report: func(ready bool, err error) {
			if ready || !errors.Is(err, revisionChanged) {
				t.Error("fixture did not retire its prepared integration revision", err)
			}
			if parentCalls.Load() != 0 || publication.Err() != nil {
				t.Error("integration attempt cleanup started foreground shutdown")
			}
			reports++
			if reports == 2 {
				stopAttachment()
			}
		}}
	if err := worker.Maintain(attachment); err != nil {
		t.Fatal("recovered integration attempts contaminated final shutdown", err)
	}
	if reports != 2 || prepared != 2 || closed != 2 || cleared < 2 || cleanupQueries.Load() < 2 || parentCalls.Load() != 0 || publication.Err() != nil {
		t.Fatal("did not join two real run attempts while retaining foreground ownership",
			reports, prepared, closed, cleared, cleanupQueries.Load(), parentCalls.Load(), publication.Err())
	}
	until := last.ShutdownDeadline()
	if until != deadline() || last.ShutdownContext != fence || parentCalls.Load() != 1 || publication.Err() == nil || fence.Err() != nil {
		t.Fatal("actual attachment stop did not borrow the original parent deadline and live fence", until, parentCalls.Load(), publication.Err(), fence.Err())
	}
}
