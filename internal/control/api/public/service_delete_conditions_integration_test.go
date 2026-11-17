package public

import (
	"errors"
	"net/http/httptest"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceDeleteRevisionManagementBoundary(t *testing.T) {
	for _, change := range []string{"metadata", "configuration", "exposure", "enablement"} {
		t.Run(change, func(t *testing.T) {
			f, session, recipient, _, service := serviceFixture(t)
			ctx := t.Context()
			h, err := NewHandler(Config{}, DatabaseStores(f.d), f.d, nil)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(h)
			t.Cleanup(server.Close)
			owner, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(session.AccessToken))
			if err != nil {
				t.Fatal(err)
			}
			visitor, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(recipient.AccessToken))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.d.CreateServiceGrant(ctx, service.ID, session.Identity.Identity.Id, "delete-visitor", "identity", recipient.Identity.Identity.Id, nil, f.now); err != nil {
				t.Fatal(err)
			}
			old, err := owner.GetService(ctx, service.ID)
			if err != nil || old.ServiceRevision < 1 {
				t.Fatal("management GET did not carry its service revision", err)
			}
			var problem *clientcontrol.ProblemError
			if err := owner.DeleteGuestService(ctx, service.ID); !errors.As(err, &problem) ||
				problem.Status != 400 || problem.Problem.Code != controlv1.InvalidRequest {
				t.Fatal("management credential bypassed deletion conditions through guest cleanup", err)
			}
			if hidden, err := visitor.GetService(ctx, service.ID); !errors.Is(err, clientcontrol.ErrNotFound) || hidden.ServiceRevision != 0 {
				t.Fatal("visitor grant exposed management revision", err)
			}
			if err := visitor.DeleteService(ctx, service.ID, controlv1.DeleteServiceParams{UnconditionalDelete: new(true)}); !errors.Is(err, clientcontrol.ErrNotFound) {
				t.Fatal("unconditional choice bypassed exact management scope", err)
			}
			var updated controlv1.Service
			if change == "enablement" {
				updated, err = owner.SetServiceEnabled(ctx, service.ID, false)
			} else {
				body := controlv1.UpdateServiceRequest{Protocol: old.Protocol, PublisherPool: old.PublisherPool, ExpectedTrustRevision: old.TrustRevision}
				if change == "metadata" {
					body.PublisherPool = !old.PublisherPool
				} else {
					_, digest, readErr := owner.GetServiceConfiguration(ctx, service.ID)
					if readErr != nil {
						t.Fatal(readErr)
					}
					body.ExpectedConfigurationDigest = &digest
					body.Configuration = &controlv1.ProjectServiceConfiguration{Target: "origin.internal:3000"}
					if change == "exposure" {
						body.Configuration.Public = new(true)
					}
				}
				updated, err = owner.ConfigureService(ctx, service.ID, body)
			}
			if err != nil || updated.ServiceRevision <= old.ServiceRevision || updated.TrustRevision != old.TrustRevision {
				t.Fatal("saved settings failed to advance independent service revision", err)
			}
			if err := owner.DeleteService(ctx, service.ID, controlv1.DeleteServiceParams{ExpectedServiceRevision: &old.ServiceRevision}); !errors.Is(err, clientcontrol.ErrStatusConflict) {
				t.Fatal("stale deletion did not return conflict through native client", err)
			}
			current, err := owner.GetService(ctx, service.ID)
			if err != nil || current.ServiceRevision != updated.ServiceRevision || current.Enabled != updated.Enabled {
				t.Fatal("stale deletion changed current service", err)
			}
			conditions := controlv1.DeleteServiceParams{ExpectedServiceRevision: &current.ServiceRevision}
			if change == "exposure" || change == "enablement" {
				conditions = controlv1.DeleteServiceParams{UnconditionalDelete: new(true)}
			}
			if err := owner.DeleteService(ctx, service.ID, conditions); err != nil {
				t.Fatal("matching or explicit unconditional deletion failed", err)
			}
		})
	}
}
